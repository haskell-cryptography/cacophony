{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
module Client
  ( runClient
  ) where

import Control.Lens       ((.~), (&))
import Data.Bits          ((.&.), shiftR)
import Data.ByteString    (ByteString, pack, length)
import qualified Data.ByteString.Char8 as C8 (pack, unpack)
import Data.IORef
import Data.Monoid        ((<>))
import Network.Simple.TCP
import Prelude hiding     (length)

import Crypto.Noise
import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.AESGCM
import Crypto.Noise.DH
import Crypto.Noise.HandshakePatterns (noiseIK)
import Crypto.Noise.Hash
import Crypto.Noise.Hash.SHA256
import Data.ByteArray.Extend hiding (length)

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

messageLoop :: (Cipher c, DH d, Hash h)
            => IORef ByteString
            -> Socket
            -> NoiseState c d h
            -> IO ()
messageLoop bufRef sock = loop
  where
    loop ns = do
      msg <- convert . C8.pack <$> getLine

      let (ct, ns') = either (error . show) id $ writeMessage ns msg
      writeSocket sock ct

      maybeMessage <- parseSocket bufRef sock messageParser
      case maybeMessage of
        Nothing -> return ()
        Just m  -> do
          let (pt, ns'')  = either (error . show) id $ readMessage ns' m
          putStrLn . ("received: " <>) . C8.unpack . convert $ pt

          loop ns''

runClient :: forall d. DH d
          => String
          -> String
          -> Maybe ScrubbedBytes
          -> KeyPair d
          -> PublicKey d
          -> IO ()
runClient hostname port psk localKey remoteKey =
  connect hostname port $ \(sock, _) -> do
    leftoverBufRef <- newIORef ""

    lek <- dhGenKey :: IO (KeyPair d)

    let dho = defaultHandshakeOpts noiseIK InitiatorRole
        hdr = maybe "\x00\x09\x01\x00\x00" (const "\x01\x09\x01\x00\x00") psk
        ho  = dho & hoPrologue       .~ convert hdr
                  & hoPreSharedKey   .~ psk
                  & hoLocalStatic    .~ Just localKey
                  & hoLocalEphemeral .~ Just lek
                  & hoRemoteStatic   .~ Just remoteKey

        ns :: NoiseState AESGCM d SHA256
        ns = noiseState ho

    send sock hdr
    putStrLn "connection established, begin typing"

    messageLoop leftoverBufRef sock ns

    putStrLn "connection closed"
