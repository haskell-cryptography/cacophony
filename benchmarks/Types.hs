{-# LANGUAGE RecordWildCards, RankNTypes, KindSignatures, GADTs #-}
module Types where

import Data.Monoid ((<>))

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


