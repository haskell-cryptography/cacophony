{-# LANGUAGE RecordWildCards, RankNTypes, GADTs, KindSignatures #-}
module Types where

import Data.Attoparsec.ByteString.Char8
import Data.Maybe  (fromMaybe)
import Data.Monoid ((<>))
import Data.Tuple  (swap)

import Crypto.Noise
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Cipher.AESGCM
import Crypto.Noise.DH.Curve25519
import Crypto.Noise.DH.Curve448
import Crypto.Noise.HandshakePatterns
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Hash.SHA512
import Crypto.Noise.Hash.BLAKE2s
import Crypto.Noise.Hash.BLAKE2b

data InputFormat
  = FormatPlain
  | FormatHex
  | FormatBase64

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

data HandshakeName = HandshakeName
  { hsPatternName :: PatternName
  , hsCipher      :: SomeCipherType
  , hsDH          :: SomeDHType
  , hsHash        :: SomeHashType
  }

data CipherType :: * -> * where
  ChaChaPoly1305 :: CipherType ChaChaPoly1305
  AESGCM         :: CipherType AESGCM

data SomeCipherType where
  WrapCipherType :: forall c. Cipher c => CipherType c -> SomeCipherType

data DHType :: * -> * where
  Curve25519 :: DHType Curve25519
  Curve448   :: DHType Curve448

data SomeDHType where
  WrapDHType :: forall d. DH d => DHType d -> SomeDHType

data HashType :: * -> * where
  BLAKE2b :: HashType BLAKE2b
  BLAKE2s :: HashType BLAKE2s
  SHA256  :: HashType SHA256
  SHA512  :: HashType SHA512

data SomeHashType where
  WrapHashType :: forall h. Hash h => HashType h -> SomeHashType

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

instance Show InputFormat where
  show FormatPlain  = "plain"
  show FormatHex    = "hex"
  show FormatBase64 = "base64"

instance Show HandshakeName where
  show HandshakeName{..} = "Noise_"
                          <> show hsPatternName
                          <> "_"
                          <> show hsDH
                          <> "_"
                          <> show hsCipher
                          <> "_"
                          <> show hsHash

instance Show PatternName where
  show = fromMaybe "unknown" . flip lookup (map swap patternMap)

instance Show SomeCipherType where
  show (WrapCipherType ChaChaPoly1305) = "ChaChaPoly"
  show (WrapCipherType AESGCM)         = "AESGCM"

instance Show SomeDHType where
  show (WrapDHType Curve25519) = "25519"
  show (WrapDHType Curve448)   = "448"

instance Show SomeHashType where
  show (WrapHashType BLAKE2b) = "BLAKE2b"
  show (WrapHashType BLAKE2s) = "BLAKE2s"
  show (WrapHashType SHA256)  = "SHA256"
  show (WrapHashType SHA512)  = "SHA512"
