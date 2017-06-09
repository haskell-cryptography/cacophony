{-# LANGUAGE RecordWildCards #-}
module VectorFile where

import Control.Monad      (mzero)
import Data.Aeson
import Data.Attoparsec.ByteString.Char8
import Data.ByteArray     (ScrubbedBytes, convert)
import Data.ByteString    (ByteString)
import qualified Data.ByteString.Base16 as B16
import Data.Monoid        ((<>))
import Data.Text          (Text)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)

data CipherName
  = CipherAESGCM
  | CipherChaChaPoly
  deriving (Show, Enum, Bounded)

data DHName
  = Curve25519
  | Curve448
  deriving (Show, Enum, Bounded)

data HashName
  = HashBLAKE2b
  | HashBLAKE2s
  | HashSHA256
  | HashSHA512
  deriving (Show, Enum, Bounded)

data PatternName
  = PatternNN
  | PatternKN
  | PatternNK
  | PatternKK
  | PatternNX
  | PatternKX
  | PatternXN
  | PatternIN
  | PatternXK
  | PatternIK
  | PatternXX
  | PatternIX
  | PatternN
  | PatternK
  | PatternX
  | PatternNNpsk0
  | PatternNNpsk2
  | PatternNKpsk0
  | PatternNKpsk2
  | PatternNXpsk2
  | PatternXNpsk3
  | PatternXKpsk3
  | PatternXXpsk3
  | PatternKNpsk0
  | PatternKNpsk2
  | PatternKKpsk0
  | PatternKKpsk2
  | PatternKXpsk2
  | PatternINpsk1
  | PatternINpsk2
  | PatternIKpsk1
  | PatternIKpsk2
  | PatternIXpsk2
  | PatternNpsk0
  | PatternKpsk0
  | PatternXpsk1
  deriving (Eq, Show, Enum, Bounded)

data HandshakeName = HandshakeName
  { hsPatternName :: PatternName
  , hsCipherName  :: CipherName
  , hsDHName      :: DHName
  , hsHashName    :: HashName
  } deriving Show

instance ToJSON HandshakeName where
  toJSON = undefined

instance FromJSON HandshakeName where
  parseJSON = undefined

parseHandshakeName :: Parser HandshakeName
parseHandshakeName = do
  _ <- string "Noise_"

  let untilUnderscore = anyChar `manyTill'` (char '_')
      untilEOI        = anyChar `manyTill'` endOfInput

  patternS <- untilUnderscore
  dhS   <- untilUnderscore
  cipherS  <- untilUnderscore
  hashS    <- untilEOI

  pattern <- case patternS of
    "NN" -> return PatternNN
    "KN" -> return PatternKN
    "NK" -> return PatternNK
    "KK" -> return PatternKK
    "NX" -> return PatternNX
    "KX" -> return PatternKX
    "XN" -> return PatternXN
    "IN" -> return PatternIN
    "XK" -> return PatternXK
    "IK" -> return PatternIK
    "XX" -> return PatternXX
    "IX" -> return PatternIX
    "N"  -> return PatternN
    "K"  -> return PatternK
    "X"  -> return PatternX
    "NNpsk0" -> return PatternNNpsk0
    "NNpsk2" -> return PatternNNpsk2
    "NKpsk0" -> return PatternNKpsk0
    "NKpsk2" -> return PatternNKpsk2
    "NXpsk2" -> return PatternNXpsk2
    "XNpsk3" -> return PatternXNpsk3
    "XKpsk3" -> return PatternXKpsk3
    "XXpsk3" -> return PatternXXpsk3
    "KNpsk0" -> return PatternKNpsk0
    "KNpsk2" -> return PatternKNpsk2
    "KKpsk0" -> return PatternKKpsk0
    "KKpsk2" -> return PatternKKpsk2
    "KXpsk2" -> return PatternKXpsk2
    "INpsk1" -> return PatternINpsk1
    "INpsk2" -> return PatternINpsk2
    "IKpsk1" -> return PatternIKpsk1
    "IKpsk2" -> return PatternIKpsk2
    "IXpsk2" -> return PatternIXpsk2
    "Npsk0"  -> return PatternNpsk0
    "Kpsk0"  -> return PatternKpsk0
    "Xpsk1"  -> return PatternXpsk1
    _    -> fail $ "unknown pattern: " <> patternS

  dh <- case dhS of
    "25519" -> return Curve25519
    "448"   -> return Curve448
    _       -> fail $ "unknown DH: " <> dhS

  cipher <- case cipherS of
    "AESGCM"     -> return CipherAESGCM
    "ChaChaPoly" -> return CipherChaChaPoly
    _            -> fail $ "unknown cipher: " <> cipherS

  hash <- case hashS of
    "BLAKE2b" -> return HashBLAKE2b
    "BLAKE2s" -> return HashBLAKE2s
    "SHA256"  -> return HashSHA256
    "SHA512"  -> return HashSHA512
    _         -> fail $ "unknown hash: " <> hashS

  return $ HandshakeName pattern cipher dh hash

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
  Vector { vName       :: HandshakeName
         , vFail       :: Bool
         , viPrologue  :: ScrubbedBytes
         , viPSK       :: Maybe ScrubbedBytes
         , viEphemeral :: Maybe ScrubbedBytes
         , viStatic    :: Maybe ScrubbedBytes
         , virStatic   :: Maybe ScrubbedBytes
         , vrPrologue  :: ScrubbedBytes
         , vrPSK       :: Maybe ScrubbedBytes
         , vrEphemeral :: Maybe ScrubbedBytes
         , vrStatic    :: Maybe ScrubbedBytes
         , vrrStatic   :: Maybe ScrubbedBytes
         , vMessages   :: [Message]
         }

instance ToJSON Vector where
  toJSON Vector{..} = object . stripDefaults . noNulls $
    [ "name"                      .= vName
    , "fail"                      .= vFail
    , "init_prologue"             .= encodeSB viPrologue
    , "init_psk"                  .= (encodeSB <$> viPSK)
    , "init_ephemeral"            .= (encodeSB <$> viEphemeral)
    , "init_static"               .= (encodeSB <$> viStatic)
    , "init_remote_static"        .= (encodeSB <$> virStatic)
    , "resp_prologue"             .= encodeSB vrPrologue
    , "resp_psk"                  .= (encodeSB <$> vrPSK)
    , "resp_ephemeral"            .= (encodeSB <$> vrEphemeral)
    , "resp_static"               .= (encodeSB <$> vrStatic)
    , "resp_remote_static"        .= (encodeSB <$> vrrStatic)
    , "messages"                  .= vMessages
    ]

    where
      noNulls       = filter (\(_, v) -> v /= Null)
      stripDefaults = filter (\(k, v) -> not (k == "fail" && v == Bool False))

instance FromJSON Vector where
  parseJSON (Object o) =
    Vector <$> o .:  "name"
           <*> o .:? "fail" .!= False
           <*> (decodeSB      <$> o .:  "init_prologue")
           <*> (fmap decodeSB <$> o .:? "init_psk")
           <*> (fmap decodeSB <$> o .:? "init_ephemeral")
           <*> (fmap decodeSB <$> o .:? "init_static")
           <*> (fmap decodeSB <$> o .:? "init_remote_static")
           <*> (decodeSB      <$> o .:  "resp_prologue")
           <*> (fmap decodeSB <$> o .:? "resp_psk")
           <*> (fmap decodeSB <$> o .:? "resp_ephemeral")
           <*> (fmap decodeSB <$> o .:? "resp_static")
           <*> (fmap decodeSB <$> o .:? "resp_remote_static")
           <*> o .: "messages"

  parseJSON _          = mzero

newtype VectorFile = VectorFile { vfVectors  :: [Vector] }

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
