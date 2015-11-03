{-# LANGUAGE DeriveGeneric, RankNTypes, ImpredicativeTypes,
    OverloadedStrings #-}

module Handshakes
  ( processHandshake
  ) where

import Control.Concurrent.MVar  (MVar, newEmptyMVar, putMVar, takeMVar)
import Control.Exception        (Exception, throw, throwIO)
import Control.Monad            (unless)
import Data.Aeson               (ToJSON, FromJSON, parseJSON, (.:),
                                 Value(..), (.=), toJSON, object, withObject)
import qualified Data.ByteArray as BA (concat)
import Data.ByteString          (ByteString)
import qualified Data.ByteString.Base64 as B64 (encode, decode)
import Data.Maybe               (isNothing, fromJust)
import Data.Text                (Text)
import Data.Text.Encoding       (encodeUtf8, decodeUtf8)
import qualified Data.Text as T (concat)
import Data.Typeable            (Typeable)
import GHC.Generics
import Pipes
import Pipes.Aeson
import Pipes.Parse

import Crypto.Noise.Descriptors
import Crypto.Noise.Handshake
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Types

data HandshakeException = HandshakeFailed
                        | InvalidHandshakeType Text
                        | Base64DecodingFailure String
  deriving (Show, Typeable)

instance Exception HandshakeException

data HandshakeType = NoiseNN
                   | NoiseKN
                   | NoiseNK
                   | NoiseKK
                   | NoiseNE
                   | NoiseKE
                   | NoiseNX
                   | NoiseKX
                   | NoiseXN
                   | NoiseIN
                   | NoiseXK
                   | NoiseIK
                   | NoiseXE
                   | NoiseIE
                   | NoiseXX
                   | NoiseIX

instance FromJSON HandshakeType where
  parseJSON (String ht)
    | ht == makeHSN' "NN" = pure NoiseNN
    | ht == makeHSN' "KN" = pure NoiseKN
    | ht == makeHSN' "NK" = pure NoiseNK
    | ht == makeHSN' "KK" = pure NoiseKK
    | ht == makeHSN' "NE" = pure NoiseNE
    | ht == makeHSN' "KE" = pure NoiseKE
    | ht == makeHSN' "NX" = pure NoiseNX
    | ht == makeHSN' "KX" = pure NoiseKX
    | ht == makeHSN' "XN" = pure NoiseXN
    | ht == makeHSN' "IN" = pure NoiseIN
    | ht == makeHSN' "XK" = pure NoiseXK
    | ht == makeHSN' "IK" = pure NoiseIK
    | ht == makeHSN' "XE" = pure NoiseXE
    | ht == makeHSN' "IE" = pure NoiseIE
    | ht == makeHSN' "XX" = pure NoiseXX
    | ht == makeHSN' "IX" = pure NoiseIX
    | otherwise           = throw $ InvalidHandshakeType ht
  parseJSON _             = mzero

data InitialMessage =
  InitialMessage { handshakeType :: HandshakeType
                 } deriving (Generic)

instance FromJSON InitialMessage

newtype HandshakeMessage = HandshakeMessage ByteString

instance FromJSON HandshakeMessage where
  parseJSON = withObject "handshake data" $
    \o -> pure
          . either
          (throw . Base64DecodingFailure)
          (HandshakeMessage)
          . B64.decode
          . encodeUtf8
          =<< (o .: "handshakeData")

instance ToJSON HandshakeMessage where
  toJSON (HandshakeMessage hm) =
    object [ "handshakeData" .= encodedData ]
    where
      encodedData = decodeUtf8 . B64.encode $ hm

newtype Message = Message ByteString

instance FromJSON Message where
  parseJSON = withObject "message" $
    \o -> pure
          . either
          (throw . Base64DecodingFailure)
          (Message)
          . B64.decode
          . encodeUtf8
          =<< (o .: "message")

instance ToJSON Message where
  toJSON (Message m) =
    object [ "message" .= encodedData ]
    where
      encodedData = decodeUtf8 . B64.encode $ m

type HandshakeKeys   = (CipherState ChaChaPoly1305, CipherState ChaChaPoly1305)

type ClientReceiver  = Producer' ByteString IO ()
type ClientSender    = Consumer' ByteString IO ()

makeHSN :: ByteString -> ScrubbedBytes
makeHSN ht = (BA.concat [prefix, convert ht, suffix])
  where
    prefix = convert ("Noise_" :: ByteString) :: ScrubbedBytes
    suffix = convert ("_25519_ChaChaPoly1305_SHA256" :: ByteString)

makeHSN' :: Text -> Text
makeHSN' ht = T.concat ["Noise_", ht, "_25519_ChaChaPoly1305_SHA256"]

processHandshake :: (ClientReceiver, ClientSender) -> IO ()
processHandshake (cr, cs) = do
  hkmv <- newEmptyMVar

  mer <- evalStateT decode cr
  unless (isNothing mer) $ do
    case fromJust mer of
      Left  e -> throwIO e
      Right r -> case handshakeType r of
        NoiseNN -> runHandshake $ handleNN hkmv
        _       -> undefined

  runEffect $ cr >-> deserialize >-> echoMessage hkmv >-> serialize >-> cs
  where
    runHandshake ht = runEffect $ cr >-> deserialize >-> ht >-> serialize >-> cs

deserialize :: FromJSON a => Pipe ByteString a IO ()
deserialize = (parseForever_ decode) >-> grabResult
  where
    grabResult = do
      mer <- await
      case mer of
        Left  e -> lift $ throwIO e
        Right r -> yield r
      grabResult

serialize :: ToJSON a => Pipe a ByteString IO ()
serialize = encodeResult >-> for cat encodeObject
  where
    encodeResult = do
      hm <- await
      case toJSON hm of
        (Object o) -> yield o
        _          -> undefined
      encodeResult

echoMessage :: MVar HandshakeKeys -> Pipe Message Message IO ()
echoMessage hkmv = do
  msg <- await

  (decryption, encryption) <- lift $ takeMVar hkmv
  let (pt, decryption') = decryptPayload (msgData msg) decryption
      (ct, encryption') = encryptPayload pt encryption
  lift $ putMVar hkmv (decryption', encryption')

  yield . Message $ ct

  return ()
  where
    msgData (Message m) = m

handleNN :: MVar HandshakeKeys -> Pipe HandshakeMessage HandshakeMessage IO ()
handleNN hkmv = do
  msg1 <- await

  let ctx = handshakeState
            (makeHSN "NN")
            Nothing
            Nothing
            Nothing
            Nothing
            Nothing
            :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
      (pt, ctx') = readHandshakeMsg ctx (msgData msg1) noiseNNR1

  (response, cs1, cs2) <- lift $ writeHandshakeMsgFinal ctx' noiseNNR2 pt
  lift $ putMVar hkmv (cs1, cs2)

  yield . HandshakeMessage $ response
  return ()
  where
    msgData (HandshakeMessage m) = m
