{-# LANGUAGE RecordWildCards, RankNTypes, GADTs, KindSignatures #-}
module VectorFile where

import Control.Monad      (mzero)
import Data.Aeson
import Data.Aeson.Types   (typeMismatch)
import Data.Attoparsec.ByteString.Char8
import Data.ByteArray     (ScrubbedBytes, convert)
import qualified Data.ByteString.Base16 as B16
import Data.Monoid        ((<>))
import Data.Text          (Text, pack)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)

import Crypto.Noise
import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Cipher.AESGCM
import Crypto.Noise.DH
import Crypto.Noise.DH.Curve25519
import Crypto.Noise.DH.Curve448
import Crypto.Noise.HandshakePatterns
import Crypto.Noise.Hash hiding (hash)
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Hash.SHA512
import Crypto.Noise.Hash.BLAKE2s
import Crypto.Noise.Hash.BLAKE2b

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
  deriving (Eq, Enum, Bounded)

instance Show PatternName where
  show PatternNN = "NN"
  show PatternKN = "KN"
  show PatternNK = "NK"
  show PatternKK = "KK"
  show PatternNX = "NX"
  show PatternKX = "KX"
  show PatternXN = "XN"
  show PatternIN = "IN"
  show PatternXK = "XK"
  show PatternIK = "IK"
  show PatternXX = "XX"
  show PatternIX = "IX"
  show PatternN  = "N"
  show PatternK  = "K"
  show PatternX  = "X"
  show PatternNNpsk0 = "NNpsk0"
  show PatternNNpsk2 = "NNpsk2"
  show PatternNKpsk0 = "NKpsk0"
  show PatternNKpsk2 = "NKpsk2"
  show PatternNXpsk2 = "NXpsk2"
  show PatternXNpsk3 = "XNpsk3"
  show PatternXKpsk3 = "XKpsk3"
  show PatternXXpsk3 = "XXpsk3"
  show PatternKNpsk0 = "KNpsk0"
  show PatternKNpsk2 = "KNpsk2"
  show PatternKKpsk0 = "KKpsk0"
  show PatternKKpsk2 = "KKpsk2"
  show PatternKXpsk2 = "KXpsk2"
  show PatternINpsk1 = "INpsk1"
  show PatternINpsk2 = "INpsk2"
  show PatternIKpsk1 = "IKpsk1"
  show PatternIKpsk2 = "IKpsk2"
  show PatternIXpsk2 = "IXpsk2"
  show PatternNpsk0  = "Npsk0"
  show PatternKpsk0  = "Kpsk0"
  show PatternXpsk1  = "Xpsk1"

data HandshakeName = HandshakeName
  { hsPatternName :: PatternName
  , hsCipher      :: SomeCipherType
  , hsDH          :: SomeDHType
  , hsHash        :: SomeHashType
  }

instance Show HandshakeName where
  show HandshakeName{..} = "Noise_"
                          <> show hsPatternName
                          <> "_"
                          <> show hsDH
                          <> "_"
                          <> show hsCipher
                          <> "_"
                          <> show hsHash

instance FromJSON HandshakeName where
  parseJSON (String s) =
    either (const mzero) pure $ parseOnly parseHandshakeName (encodeUtf8 s)
  parseJSON bad        = typeMismatch "HandshakeName" bad

instance ToJSON HandshakeName where
  toJSON = String . pack . show

data CipherType :: * -> * where
  ChaChaPoly1305 :: CipherType ChaChaPoly1305
  AESGCM         :: CipherType AESGCM

data SomeCipherType where
  WrapCipherType :: forall c. Cipher c => CipherType c -> SomeCipherType

instance Show SomeCipherType where
  show (WrapCipherType ChaChaPoly1305) = "ChaChaPoly"
  show (WrapCipherType AESGCM)         = "AESGCM"

data DHType :: * -> * where
  Curve25519 :: DHType Curve25519
  Curve448   :: DHType Curve448

data SomeDHType where
  WrapDHType :: forall d. DH d => DHType d -> SomeDHType

instance Show SomeDHType where
  show (WrapDHType Curve25519) = "25519"
  show (WrapDHType Curve448)   = "448"

data HashType :: * -> * where
  BLAKE2b :: HashType BLAKE2b
  BLAKE2s :: HashType BLAKE2s
  SHA256  :: HashType SHA256
  SHA512  :: HashType SHA512

data SomeHashType where
  WrapHashType :: forall h. Hash h => HashType h -> SomeHashType

instance Show SomeHashType where
  show (WrapHashType BLAKE2b) = "BLAKE2b"
  show (WrapHashType BLAKE2s) = "BLAKE2s"
  show (WrapHashType SHA256)  = "SHA256"
  show (WrapHashType SHA512)  = "SHA512"

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

patternMap :: [(String, PatternName)]
patternMap =
  [ ("NN", PatternNN)
  , ("KN", PatternKN)
  , ("NK", PatternNK)
  , ("KK", PatternKK)
  , ("NX", PatternNX)
  , ("KX", PatternKX)
  , ("XN", PatternXN)
  , ("IN", PatternIN)
  , ("XK", PatternXK)
  , ("IK", PatternIK)
  , ("XX", PatternXX)
  , ("IX", PatternIX)
  , ("N" , PatternN)
  , ("K" , PatternK)
  , ("X" , PatternX)
  , ("NNpsk0", PatternNNpsk0)
  , ("NNpsk2", PatternNNpsk2)
  , ("NKpsk0", PatternNKpsk0)
  , ("NKpsk2", PatternNKpsk2)
  , ("NXpsk2", PatternNXpsk2)
  , ("XNpsk3", PatternXNpsk3)
  , ("XKpsk3", PatternXKpsk3)
  , ("XXpsk3", PatternXXpsk3)
  , ("KNpsk0", PatternKNpsk0)
  , ("KNpsk2", PatternKNpsk2)
  , ("KKpsk0", PatternKKpsk0)
  , ("KKpsk2", PatternKKpsk2)
  , ("KXpsk2", PatternKXpsk2)
  , ("INpsk1", PatternINpsk1)
  , ("INpsk2", PatternINpsk2)
  , ("IKpsk1", PatternIKpsk1)
  , ("IKpsk2", PatternIKpsk2)
  , ("IXpsk2", PatternIXpsk2)
  , ("Npsk0" , PatternNpsk0)
  , ("Kpsk0" , PatternKpsk0)
  , ("Xpsk1" , PatternXpsk1)
  ]

dhMap :: [(String, SomeDHType)]
dhMap =
  [ ("25519", WrapDHType Curve25519)
  , ("448"  , WrapDHType Curve448)
  ]

cipherMap :: [(String, SomeCipherType)]
cipherMap =
  [ ("AESGCM"    , WrapCipherType AESGCM)
  , ("ChaChaPoly", WrapCipherType ChaChaPoly1305)
  ]

hashMap :: [(String, SomeHashType)]
hashMap =
  [ ("BLAKE2b", WrapHashType BLAKE2b)
  , ("BLAKE2s", WrapHashType BLAKE2s)
  , ("SHA256" , WrapHashType SHA256)
  , ("SHA512" , WrapHashType SHA512)
  ]

parseHandshakeName :: Parser HandshakeName
parseHandshakeName = do
  _ <- string "Noise_"

  let untilUnderscore = anyChar `manyTill'` (char '_')
      untilEOI        = anyChar `manyTill'` endOfInput

  pattern <- (flip lookup patternMap) <$> untilUnderscore
  dh      <- (flip lookup dhMap)      <$> untilUnderscore
  cipher  <- (flip lookup cipherMap)  <$> untilUnderscore
  hash    <- (flip lookup hashMap)    <$> untilEOI


  let mHandshakeName = do
        p <- pattern
        d <- dh
        c <- cipher
        h <- hash

        return $ HandshakeName p c d h

  maybe mempty return mHandshakeName

patternToHandshake :: PatternName
                   -> HandshakePattern
patternToHandshake PatternNN = noiseNN
patternToHandshake PatternKN = noiseKN
patternToHandshake PatternNK = noiseNK
patternToHandshake PatternKK = noiseKK
patternToHandshake PatternNX = noiseNX
patternToHandshake PatternKX = noiseKX
patternToHandshake PatternXN = noiseXN
patternToHandshake PatternIN = noiseIN
patternToHandshake PatternXK = noiseXK
patternToHandshake PatternIK = noiseIK
patternToHandshake PatternXX = noiseXX
patternToHandshake PatternIX = noiseIX
patternToHandshake PatternN  = noiseN
patternToHandshake PatternK  = noiseK
patternToHandshake PatternX  = noiseX
patternToHandshake PatternNNpsk0 = noiseNNpsk0
patternToHandshake PatternNNpsk2 = noiseNNpsk2
patternToHandshake PatternNKpsk0 = noiseNKpsk0
patternToHandshake PatternNKpsk2 = noiseNKpsk2
patternToHandshake PatternNXpsk2 = noiseNXpsk2
patternToHandshake PatternXNpsk3 = noiseXNpsk3
patternToHandshake PatternXKpsk3 = noiseXKpsk3
patternToHandshake PatternXXpsk3 = noiseXXpsk3
patternToHandshake PatternKNpsk0 = noiseKNpsk0
patternToHandshake PatternKNpsk2 = noiseKNpsk2
patternToHandshake PatternKKpsk0 = noiseKKpsk0
patternToHandshake PatternKKpsk2 = noiseKKpsk2
patternToHandshake PatternKXpsk2 = noiseKXpsk2
patternToHandshake PatternINpsk1 = noiseINpsk1
patternToHandshake PatternINpsk2 = noiseINpsk2
patternToHandshake PatternIKpsk1 = noiseIKpsk1
patternToHandshake PatternIKpsk2 = noiseIKpsk2
patternToHandshake PatternIXpsk2 = noiseIXpsk2
patternToHandshake PatternNpsk0  = noiseNpsk0
patternToHandshake PatternKpsk0  = noiseKpsk0
patternToHandshake PatternXpsk1  = noiseXpsk1

encodeSB :: ScrubbedBytes
         -> Text
encodeSB = decodeUtf8 . B16.encode . convert

decodeSB :: Text
         -> ScrubbedBytes
decodeSB = convert . fst . B16.decode . encodeUtf8
