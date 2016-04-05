{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
module Client
  ( runClient
  ) where

import Data.Bits                  ((.&.), shiftR)
import Data.ByteString            (ByteString, pack, length)
import qualified Data.ByteString.Char8 as C8 (pack, unpack)
import Data.IORef
import Data.Maybe (fromMaybe)
import Data.Monoid                ((<>))
import Network.Simple.TCP
import Prelude hiding             (length)

import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.AESGCM
import Crypto.Noise.Curve
import Crypto.Noise.Handshake
import Crypto.Noise.HandshakePatterns (noiseIK)
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Types
import Data.ByteArray.Extend

import Parse

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
readSocket bufRef sock = fromMaybe "" <$> parseSocket bufRef sock messageParser

header :: ByteString
header = "\x09\x01\x00\x00"

messageLoop :: Cipher c
            => IORef ByteString
            -> Socket
            -> SendingCipherState c
            -> ReceivingCipherState c
            -> IO ()
messageLoop bufRef sock = loop
  where
    loop scs rcs = do
      msg <- Plaintext . bsToSB' . C8.pack <$> getLine

      let (ct, scs') = encryptPayload msg scs
      writeSocket sock ct

      maybeMessage <- parseSocket bufRef sock messageParser
      case maybeMessage of
        Nothing -> return ()
        Just m  -> do
          let (Plaintext pt, rcs') = decryptPayload m rcs
          putStrLn . ("received: " <>) . C8.unpack . sbToBS' $ pt

          loop scs' rcs'

runClient :: forall d. Curve d
          => String
          -> String
          -> Plaintext
          -> Maybe Plaintext
          -> KeyPair d
          -> PublicKey d
          -> IO ()
runClient hostname port prologue psk localKey remoteKey =
  connect hostname port $ \(sock, _) -> do
    putStrLn "connected"

    leftoverBufRef <- newIORef ""

    let hc = HandshakeCallbacks (writeSocket sock)
                                (readSocket leftoverBufRef sock)
                                (\_ -> return ())
                                (return "")
                                (\_ -> return True)

        hs :: HandshakeState AESGCM d SHA256
        hs = handshakeState $ HandshakeOpts
          noiseIK
          prologue
          psk
          (Just localKey)
          Nothing
          (Just remoteKey)
          Nothing
          True

    send sock header
    (encryptionCipherState, decryptionCipherState) <- runHandshake hs hc
    putStrLn "handshake complete, begin typing"

    messageLoop leftoverBufRef sock encryptionCipherState decryptionCipherState
