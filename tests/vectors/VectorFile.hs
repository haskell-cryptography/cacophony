{-# LANGUAGE OverloadedStrings, RecordWildCards #-}
module VectorFile where

import Control.Monad      (mzero)
import Data.Aeson
import Data.ByteString    (ByteString)
import qualified Data.ByteString.Base16 as B16
import Data.Text          (Text)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)

import Data.ByteArray.Extend

import Types

data Message =
  Message { mPayload    :: Maybe ScrubbedBytes
          , mCiphertext :: ByteString
          } deriving (Eq, Show)

instance ToJSON Message where
  toJSON Message{..} =
    object [ "payload"    .= ((decodeUtf8 . B16.encode . convert) <$> mPayload)
           , "ciphertext" .= (decodeUtf8 . B16.encode) mCiphertext
           ]

instance FromJSON Message where
  parseJSON (Object o) =
    Message <$> (fmap (convert . fst . B16.decode . encodeUtf8) <$> o .:? "payload")
            <*> ((fst . B16.decode . encodeUtf8) <$> o .: "ciphertext")

  parseJSON _          = mzero

data Vector =
  Vector { vName            :: String
         , vPattern         :: HandshakeType
         , vCipher          :: SomeCipherType
         , vDH              :: SomeDHType
         , vHash            :: SomeHashType
         , vFail            :: Bool
         , viPrologue       :: ScrubbedBytes
         , viPSK            :: Maybe ScrubbedBytes
         , viStatic         :: Maybe ScrubbedBytes
         , viSemiEphemeral  :: Maybe ScrubbedBytes
         , viEphemeral      :: Maybe ScrubbedBytes
         , virStatic        :: Maybe ScrubbedBytes
         , virSemiEphemeral :: Maybe ScrubbedBytes
         , vrPrologue       :: ScrubbedBytes
         , vrPSK            :: Maybe ScrubbedBytes
         , vrStatic         :: Maybe ScrubbedBytes
         , vrSemiEphemeral  :: Maybe ScrubbedBytes
         , vrEphemeral      :: Maybe ScrubbedBytes
         , vrrStatic        :: Maybe ScrubbedBytes
         , vrrSemiEphemeral :: Maybe ScrubbedBytes
         , vMessages        :: [Message]
         }

instance ToJSON Vector where
  toJSON Vector{..} = object . stripDefaults . noNulls $
    [ "name"                      .= vName
    , "pattern"                   .= show vPattern
    , "cipher"                    .= vCipher
    , "dh"                        .= vDH
    , "hash"                      .= vHash
    , "fail"                      .= vFail
    , "init_prologue"             .= (decodeUtf8 . B16.encode . convert) viPrologue
    , "init_psk"                  .= ((decodeUtf8 . B16.encode . convert) <$> viPSK)
    , "init_static"               .= (encodeSB <$> viStatic)
    , "init_semiephemeral"        .= (encodeSB <$> viSemiEphemeral)
    , "init_ephemeral"            .= (encodeSB <$> viEphemeral)
    , "init_remote_static"        .= (encodeSB <$> virStatic)
    , "init_remote_semiephemeral" .= (encodeSB <$> virSemiEphemeral)
    , "resp_prologue"             .= (decodeUtf8 . B16.encode . convert) vrPrologue
    , "resp_psk"                  .= ((decodeUtf8 . B16.encode . convert) <$> vrPSK)
    , "resp_static"               .= (encodeSB <$> vrStatic)
    , "resp_semiephemeral"        .= (encodeSB <$> vrSemiEphemeral)
    , "resp_ephemeral"            .= (encodeSB <$> vrEphemeral)
    , "resp_remote_static"        .= (encodeSB <$> vrrStatic)
    , "resp_remote_semiephemeral" .= (encodeSB <$> vrrSemiEphemeral)
    , "messages"                  .= vMessages
    ]

    where
      noNulls       = filter (\(_, v) -> v /= Null)
      stripDefaults = filter (\(k, v) -> not (k == "fail" && v == Bool False))

instance FromJSON Vector where
  parseJSON (Object o) =
    Vector <$> o .: "name"
           <*> (parsePattern  <$> o .: "pattern")
           <*> (parseCipher   <$> o .: "cipher")
           <*> (parseDH    <$> o .: "dh")
           <*> (parseHash     <$> o .: "hash")
           <*> o .:? "fail" .!= False
           <*> ((convert . fst . B16.decode . encodeUtf8) <$> o .: "init_prologue")
           <*> (fmap (convert . fst . B16.decode . encodeUtf8) <$> o .:? "init_psk")
           <*> (fmap decodeSB <$> o .:? "init_static")
           <*> (fmap decodeSB <$> o .:? "init_semiephemeral")
           <*> (fmap decodeSB <$> o .:? "init_ephemeral")
           <*> (fmap decodeSB <$> o .:? "init_remote_static")
           <*> (fmap decodeSB <$> o .:? "init_remote_semiephemeral")
           <*> ((convert . fst . B16.decode . encodeUtf8) <$> o .: "resp_prologue")
           <*> (fmap (convert . fst . B16.decode . encodeUtf8) <$> o .:? "resp_psk")
           <*> (fmap decodeSB <$> o .:? "resp_static")
           <*> (fmap decodeSB <$> o .:? "resp_semiephemeral")
           <*> (fmap decodeSB <$> o .:? "resp_ephemeral")
           <*> (fmap decodeSB <$> o .:? "resp_remote_static")
           <*> (fmap decodeSB <$> o .:? "resp_remote_semiephemeral")
           <*> o .: "messages"

  parseJSON _          = mzero

data VectorFile =
  VectorFile { vfVectors  :: [Vector]
             }

instance ToJSON VectorFile where
  toJSON VectorFile{..} = object [ "vectors" .= vfVectors ]

instance FromJSON VectorFile where
  parseJSON (Object o) = VectorFile <$> o .: "vectors"
  parseJSON _          = mzero

encodeSB :: ScrubbedBytes
         -> Text
encodeSB = decodeUtf8 . B16.encode . convert

decodeSB :: Text
         -> ScrubbedBytes
decodeSB = convert . fst . B16.decode . encodeUtf8

parsePattern :: Text
             -> HandshakeType
parsePattern "NN" = NoiseNN
parsePattern "KN" = NoiseKN
parsePattern "NK" = NoiseNK
parsePattern "KK" = NoiseKK
parsePattern "NX" = NoiseNX
parsePattern "KX" = NoiseKX
parsePattern "XN" = NoiseXN
parsePattern "IN" = NoiseIN
parsePattern "XK" = NoiseXK
parsePattern "IK" = NoiseIK
parsePattern "XX" = NoiseXX
parsePattern "IX" = NoiseIX
parsePattern "XR" = NoiseXR
parsePattern "N"  = NoiseN
parsePattern "K"  = NoiseK
parsePattern "X"  = NoiseX
parsePattern _    = error "invalid pattern name"

parseCipher :: Text
            -> SomeCipherType
parseCipher "ChaChaPoly" = WrapCipherType CTChaChaPoly1305
parseCipher "AESGCM"     = WrapCipherType CTAESGCM
parseCipher _            = error "invalid cipher name"

parseDH :: Text
        -> SomeDHType
parseDH "25519" = WrapDHType DTCurve25519
parseDH "448"   = WrapDHType DTCurve448
parseDH _       = error "invalid curve name"

parseHash :: Text
          -> SomeHashType
parseHash "SHA256"  = WrapHashType HTSHA256
parseHash "SHA512"  = WrapHashType HTSHA512
parseHash "BLAKE2s" = WrapHashType HTBLAKE2s
parseHash "BLAKE2b" = WrapHashType HTBLAKE2b
parseHash _         = error "invalid hash name"
