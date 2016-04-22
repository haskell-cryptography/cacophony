{-# LANGUAGE OverloadedStrings, RecordWildCards, GADTs,
    ScopedTypeVariables #-}
module Server
  ( startServer
  ) where

import Control.AutoUpdate     (mkAutoUpdate, defaultUpdateSettings, updateAction)
import Control.Exception      (handle)
import Control.Monad          (void)
import Data.Bits              ((.&.), shiftR)
import Data.ByteString        (ByteString, pack, length)
import Data.ByteString.Base16 (encode)
import qualified Data.ByteString.Char8 as C8 (pack)
import Data.IORef
import Data.Monoid            ((<>))
import Network.Simple.TCP
import Prelude hiding         (log, length)
import System.Timeout

import Crypto.Noise
import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash
import Data.ByteArray.Extend hiding (length)

import Handshakes
import Log
import Parse
import Types

mkHandshakeKeys :: forall d. DH d
                => ScrubbedBytes
                -> Bool
                -> ServerOpts
                -> DHType d
                -> IO (HandshakeKeys d)
mkHandshakeKeys pro psk ServerOpts{..} DTCurve25519 = do
  lek <- dhGenKey :: IO (KeyPair d)

  return
    HandshakeKeys { hkPrologue       = pro
                  , hkPSK            = if psk then Just soPSK else Nothing
                  , hkLocalStatic    = soLocal25519
                  , hkLocalEphemeral = lek
                  , hkRemoteStatic   = soRemote25519
                  }

mkHandshakeKeys pro psk ServerOpts{..} DTCurve448 = do
  lek <- dhGenKey :: IO (KeyPair d)

  return
    HandshakeKeys { hkPrologue       = pro
                  , hkPSK            = if psk then Just soPSK else Nothing
                  , hkLocalStatic    = soLocal448
                  , hkLocalEphemeral = lek
                  , hkRemoteStatic   = soRemote448
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

mkProtocolName :: ServerOpts
               -> Header
               -> String
mkProtocolName ServerOpts{..} (psk, hp, WrapCipherType cipherT, WrapDHType curveT, WrapHashType hashT) =
  p <> show hp <> "_" <> show curveT <> "_" <> show cipherT <> "_" <> show hashT
  where
    p = if psk then "NoisePSK_" else "Noise_"

messageLoop :: (Cipher c, DH d, Hash h)
            => IORef ByteString
            -> Socket
            -> NoiseState c d h
            -> IO ()
messageLoop bufRef sock = loop
  where
    loop ns = do
      maybeMessage <- parseSocket bufRef sock messageParser
      case maybeMessage of
        Nothing -> return ()
        Just m  -> do
          let (pt, ns')  = either (error . show) id $ readMessage ns m
              (ct, ns'') = either (error . show) id $ writeMessage ns' pt

          writeSocket sock ct
          loop ns''

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

          Just h@(psk, hp, WrapCipherType cipherT, WrapDHType curveT, WrapHashType hashT) -> do
            log ip $ "client selected " <> C8.pack (mkProtocolName opts h)

            hk <- mkHandshakeKeys (convert . serializeHeader $ h) psk opts curveT
            log ip $ "private ephemeral: " <> (encode . convert . dhSecToBytes . fst . hkLocalEphemeral) hk
            let ns  = mkNoiseState hk hp ResponderRole cipherT hashT

            void . timeout 60000000 $ messageLoop leftoverBufRef sock ns

    log ip "connection closed"
