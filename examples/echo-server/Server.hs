{-# LANGUAGE OverloadedStrings, RecordWildCards, GADTs, RankNTypes #-}
module Server
  ( startServer
  ) where

import Control.AutoUpdate         (mkAutoUpdate, defaultUpdateSettings, updateAction)
import Control.Exception          (handle)
import Control.Monad              (void)
import Data.Bits                  ((.&.), shiftR)
import Data.ByteString            (ByteString, pack, length)
import qualified Data.ByteString.Char8 as C8 (pack)
import Data.IORef
import Data.Maybe                 (fromMaybe)
import Data.Monoid                ((<>))
import Network.Simple.TCP
import Prelude hiding             (log, length)
import System.Timeout

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Handshake

import Handshakes
import Log
import Parse
import Types

mkHandshakeKeys :: Curve d
                => ServerOpts
                -> CurveType d
                -> HandshakeKeys d
mkHandshakeKeys ServerOpts{..} CTCurve25519 =
  HandshakeKeys { hkPrologue     = soPrologue
                , hkPSK          = soPSK
                , hkLocalStatic  = soLocal25519
                , hkRemoteStatic = soRemote25519
                }

mkHandshakeKeys ServerOpts{..} CTCurve448 =
  HandshakeKeys { hkPrologue     = soPrologue
                , hkPSK          = soPSK
                , hkLocalStatic  = soLocal448
                , hkRemoteStatic = soRemote448
                }

prependLength :: ByteString
              -> ByteString
prependLength msg = pack w16len <> msg
  where
    len    = length msg
    w16len = fmap fromIntegral [(len .&. 0xFF00) `shiftR` 8, len .&. 0xFF]

writeSocket :: Socket
            -> ByteString
            -> IO ()
writeSocket s msg = send s $ prependLength msg

readSocket :: IORef ByteString
           -> Socket
           -> IO ByteString
readSocket bufRef sock = fromMaybe (error "connection reset") <$> parseSocket bufRef sock messageParser

mkProtocolName :: ServerOpts
               -> Header
               -> String
mkProtocolName ServerOpts{..} (hp, WrapCipherType cipherT, WrapCurveType curveT, WrapHashType hashT) =
  psk <> show hp <> "_" <> show cipherT <> "_" <> show curveT <> "_" <> show hashT
  where
    psk = maybe "Noise_" (const "NoisePSK_") soPSK

messageLoop :: Cipher c
            => IORef ByteString
            -> Socket
            -> SendingCipherState c
            -> ReceivingCipherState c
            -> IO ()
messageLoop bufRef sock = loop
  where
    loop scs rcs = do
      maybeMessage <- parseSocket bufRef sock messageParser
      case maybeMessage of
        Nothing -> return ()
        Just m  -> do
          let (pt, rcs') = decryptPayload m rcs
              (ct, scs') = encryptPayload pt scs
          writeSocket sock ct
          loop scs' rcs'

startServer :: ServerOpts
            -> IO ()
startServer opts@ServerOpts{..} = do
  logHandle <- maybe openStdOut openLog soLogFile
  au <- mkAutoUpdate defaultUpdateSettings { updateAction = getDateTime }
  let logEx = logException logHandle au
      log   = logMsg logHandle au

  serve HostAny soPort $ \(sock, ip) -> handle (logEx ip) $ do
    log ip "connection established"

    leftoverBufRef <- newIORef ""
    th <- timeout 60000000 $ parseSocket leftoverBufRef sock headerParser
    case th of
      Nothing -> log ip "timeout waiting for header"
      Just maybeHeader ->
        case maybeHeader of
          Nothing -> do
            send sock "failed to parse header\n"
            log ip "failed to parse header"

          Just h@(hp, WrapCipherType cipherT, WrapCurveType curveT, WrapHashType hashT) -> do
            payloadRef <- newIORef ""

            log ip $ "client selected " <> C8.pack (mkProtocolName opts h)
            let hk = mkHandshakeKeys opts curveT
                hs = mkHandshake hk hp cipherT hashT
                hc = HandshakeCallbacks (writeSocket sock)
                                        (readSocket leftoverBufRef sock)
                                        (modifyIORef' payloadRef . const)
                                        (readIORef payloadRef)
                                        (\_ -> return True)
            (encryptionCipherState, decryptionCipherState) <- runHandshake hs hc

            void . timeout 60000000 $ messageLoop leftoverBufRef sock encryptionCipherState decryptionCipherState

    log ip "connection closed"
