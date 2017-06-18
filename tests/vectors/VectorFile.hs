{-# LANGUAGE RecordWildCards, RankNTypes, GADTs #-}
module VectorFile where

import Data.Aeson
import Data.Aeson.Types   (typeMismatch)
import qualified Data.ByteString.Base16 as B16
import Data.Text          (Text)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)

import Crypto.Noise

import Types

data Message =
  Message { mPayload    :: ScrubbedBytes
          , mCiphertext :: ScrubbedBytes
          } deriving (Eq, Show)

instance ToJSON Message where
  toJSON Message{..} =
    object [ "payload"    .= encodeSB mPayload
           , "ciphertext" .= encodeSB mCiphertext
           ]

instance FromJSON Message where
  parseJSON (Object o) =
    Message <$> (decodeSB <$> o .: "payload")
            <*> (decodeSB <$> o .: "ciphertext")

  parseJSON bad        = typeMismatch "Message" bad

data Vector =
  Vector { vName       :: Maybe Text
         , vProtoName  :: HandshakeName
         , vFail       :: Bool
         , viPrologue  :: ScrubbedBytes
         , viPSKs      :: [ScrubbedBytes]
         , viEphemeral :: Maybe ScrubbedBytes
         , viStatic    :: Maybe ScrubbedBytes
         , virStatic   :: Maybe ScrubbedBytes
         , vrPrologue  :: ScrubbedBytes
         , vrPSKs      :: [ScrubbedBytes]
         , vrEphemeral :: Maybe ScrubbedBytes
         , vrStatic    :: Maybe ScrubbedBytes
         , vrrStatic   :: Maybe ScrubbedBytes
         , vHash       :: Maybe ScrubbedBytes
         , vMessages   :: [Message]
         } deriving Show

instance ToJSON Vector where
  toJSON Vector{..} = object . stripDefaults . stripEmptyLists . stripNulls $
    [ "name"                      .= vName
    , "protocol_name"             .= vProtoName
    , "fail"                      .= vFail
    , "init_prologue"             .= encodeSB viPrologue
    , "init_psks"                 .= (encodeSB <$> viPSKs)
    , "init_ephemeral"            .= (encodeSB <$> viEphemeral)
    , "init_static"               .= (encodeSB <$> viStatic)
    , "init_remote_static"        .= (encodeSB <$> virStatic)
    , "resp_prologue"             .= encodeSB vrPrologue
    , "resp_psks"                 .= (encodeSB <$> vrPSKs)
    , "resp_ephemeral"            .= (encodeSB <$> vrEphemeral)
    , "resp_static"               .= (encodeSB <$> vrStatic)
    , "resp_remote_static"        .= (encodeSB <$> vrrStatic)
    , "handshake_hash"            .= (encodeSB <$> vHash)
    , "messages"                  .= vMessages
    ]

    where
      stripNulls       = filter (\(_, v) -> v /= Null)
      stripEmptyLists  = filter (\(_, v) -> v /= Array mempty)
      stripDefaults    = filter (\(k, v) -> not (k == "fail" && v == Bool False))

instance FromJSON Vector where
  parseJSON (Object o) =
    Vector <$> o .:?  "name"
           <*> o .: "protocol_name"
           <*> o .:? "fail" .!= False
           <*> (decodeSB      <$> o .:  "init_prologue")
           <*> (fmap decodeSB <$> o .:? "init_psks" .!= [])
           <*> (fmap decodeSB <$> o .:? "init_ephemeral")
           <*> (fmap decodeSB <$> o .:? "init_static")
           <*> (fmap decodeSB <$> o .:? "init_remote_static")
           <*> (decodeSB      <$> o .:  "resp_prologue")
           <*> (fmap decodeSB <$> o .:? "resp_psks" .!= [])
           <*> (fmap decodeSB <$> o .:? "resp_ephemeral")
           <*> (fmap decodeSB <$> o .:? "resp_static")
           <*> (fmap decodeSB <$> o .:? "resp_remote_static")
           <*> (fmap decodeSB <$> o .:? "handshake_hash")
           <*> o .: "messages"

  parseJSON bad        = typeMismatch "Vector" bad

newtype VectorFile = VectorFile { vfVectors  :: [Vector] }

instance ToJSON VectorFile where
  toJSON VectorFile{..} = object [ "vectors" .= vfVectors ]

instance FromJSON VectorFile where
  parseJSON (Object o) = VectorFile <$> o .: "vectors"
  parseJSON bad        = typeMismatch "VectorFile" bad

encodeSB :: ScrubbedBytes
         -> Text
encodeSB = decodeUtf8 . B16.encode . convert

decodeSB :: Text
         -> ScrubbedBytes
decodeSB = convert . fst . B16.decode . encodeUtf8
