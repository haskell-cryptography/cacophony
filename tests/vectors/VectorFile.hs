{-# LANGUAGE OverloadedStrings, RecordWildCards #-}
module VectorFile where

import Control.Monad      (mzero)
import Data.Aeson
import Data.Attoparsec.ByteString.Char8
import Data.ByteArray     (ScrubbedBytes, convert)
import Data.ByteString    (ByteString)
import qualified Data.ByteString.Base16 as B16
import Data.Text          (Text)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)

data CipherName
  = CipherAESGCM
  | CipherChaChaPoly
  deriving (Enum, Bounded)

data CurveName
  = Curve25519
  | Curve448
  deriving (Enum, Bounded)

data HashName
  = HashBLAKE2b
  | HashBLAKE2s
  | HashSHA256
  | HashSHA512
  deriving (Enum, Bounded)

data PatternName
  = NoiseNN
  | NoiseKN
  | NoiseNK
  | NoiseKK
  | NoiseNX
  | NoiseKX
  | NoiseXN
  | NoiseIN
  | NoiseXK
  | NoiseIK
  | NoiseXX
  | NoiseIX
  | NoiseN
  | NoiseK
  | NoiseX
  | NoiseNNpsk0
  | NoiseNNpsk2
  | NoiseNKpsk0
  | NoiseNKpsk2
  | NoiseNXpsk2
  | NoiseXNpsk3
  | NoiseXKpsk3
  | NoiseXXpsk3
  | NoiseKNpsk0
  | NoiseKNpsk2
  | NoiseKKpsk0
  | NoiseKKpsk2
  | NoiseKXpsk2
  | NoiseINpsk1
  | NoiseINpsk2
  | NoiseIKpsk1
  | NoiseIKpsk2
  | NoiseIXpsk2
  | NoiseNpsk0
  | NoiseKpsk0
  | NoiseXpsk1
  deriving (Enum, Bounded)

data HandshakeName = HandshakeName
  { hsPatternName :: PatternName
  , hsCipherName  :: CipherName
  , hsCurveName   :: CurveName
  , hsHashName    :: HashName
  }

instance ToJSON HandshakeName where
  toJSON = undefined

instance FromJSON HandshakeName where
  parseJSON = undefined

parseHandshakeName :: Parser HandshakeName
parseHandshakeName = do
  _ <- string "Noise_"
  patternS <- anyChar `sepBy1` (char '_')
  curveS   <- anyChar `sepBy1` (char '_')
  cipherS  <- anyChar `sepBy1` (char '_')
  hashS    <- anyChar `sepBy1` endOfInput

  let pattern = case patternS of
        "NN" -> NoiseNN
        _    -> fail "unknown pattern"

      curve = case curveS of
        "25519" -> Curve25519
        "448"   -> Curve448
        _       -> fail "unknown curve"

      cipher = case cipherS of
        "AESGCM"     -> CipherAESGCM
        "ChaChaPoly" -> CipherChaChaPoly
        _            -> fail "unknown cipher"

      hash = case hashS of
        "BLAKE2b" -> HashBLAKE2b
        "BLAKE2s" -> HashBLAKE2s
        "SHA256"  -> HashSHA256
        "SHA512"  -> HashSHA512
        _         -> fail "unknown hash"

  return $ HandshakeName pattern cipher curve hash

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

allHandshakes :: [HandshakeName]
allHandshakes = do
  pattern <- [minBound .. maxBound]
  cipher  <- [minBound .. maxBound]
  curve   <- [minBound .. maxBound]
  hash    <- [minBound .. maxBound]
  return $ HandshakeName pattern cipher curve hash

{-data Vector =
  Vector { vName       :: String
         , vPattern    :: PatternName
         , vFail       :: Bool
         , viPrologue  :: ScrubbedBytes
         , viPSK       :: Maybe ScrubbedBytes
         , viStatic    :: Maybe ScrubbedBytes
         , viEphemeral :: Maybe ScrubbedBytes
         , virStatic   :: Maybe ScrubbedBytes
         , vrPrologue  :: ScrubbedBytes
         , vrPSK       :: Maybe ScrubbedBytes
         , vrStatic    :: Maybe ScrubbedBytes
         , vrEphemeral :: Maybe ScrubbedBytes
         , vrrStatic   :: Maybe ScrubbedBytes
         , vMessages   :: [Message]
         }

instance ToJSON Vector where
  toJSON Vector{..} = object . stripDefaults . noNulls $
    [ "name"                      .= vName
    , "pattern"                   .= vPattern
    , "fail"                      .= vFail
    , "init_prologue"             .= encodeSB viPrologue
    , "init_psk"                  .= (encodeSB <$> viPSK)
    , "init_static"               .= (encodeSB <$> viStatic)
    , "init_ephemeral"            .= (encodeSB <$> viEphemeral)
    , "init_remote_static"        .= (encodeSB <$> virStatic)
    , "resp_prologue"             .= encodeSB vrPrologue
    , "resp_psk"                  .= (encodeSB <$> vrPSK)
    , "resp_static"               .= (encodeSB <$> vrStatic)
    , "resp_ephemeral"            .= (encodeSB <$> vrEphemeral)
    , "resp_remote_static"        .= (encodeSB <$> vrrStatic)
    , "messages"                  .= vMessages
    ]

    where
      noNulls       = filter (\(_, v) -> v /= Null)
      stripDefaults = filter (\(k, v) -> not (k == "fail" && v == Bool False))

instance FromJSON Vector where
  parseJSON (Object o) =
    Vector <$> o .:  "name"
           <*> o .:  "pattern"
           <*> o .:? "fail" .!= False
           <*> (decodeSB      <$> o .:  "init_prologue")
           <*> (fmap decodeSB <$> o .:? "init_psk")
           <*> (fmap decodeSB <$> o .:? "init_static")
           <*> (fmap decodeSB <$> o .:? "init_ephemeral")
           <*> (fmap decodeSB <$> o .:? "init_remote_static")
           <*> (decodeSB      <$> o .:  "resp_prologue")
           <*> (fmap decodeSB <$> o .:? "resp_psk")
           <*> (fmap decodeSB <$> o .:? "resp_static")
           <*> (fmap decodeSB <$> o .:? "resp_ephemeral")
           <*> (fmap decodeSB <$> o .:? "resp_remote_static")
           <*> o .: "messages"

  parseJSON _          = mzero

newtype VectorFile = VectorFile { vfVectors  :: [Vector] }

instance ToJSON VectorFile where
  toJSON VectorFile{..} = object [ "vectors" .= vfVectors ]

instance FromJSON VectorFile where
  parseJSON (Object o) = VectorFile <$> o .: "vectors"
  parseJSON _          = mzero-}

encodeSB :: ScrubbedBytes
         -> Text
encodeSB = decodeUtf8 . B16.encode . convert

decodeSB :: Text
         -> ScrubbedBytes
decodeSB = convert . fst . B16.decode . encodeUtf8
