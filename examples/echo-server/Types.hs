{-# LANGUAGE RankNTypes, KindSignatures, GADTs #-}
module Types where

import Data.ByteArray        (ScrubbedBytes, convert)
import Data.ByteString.Char8 (unpack)

import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Cipher.AESGCM
import Crypto.Noise.DH
import Crypto.Noise.DH.Curve25519
import Crypto.Noise.DH.Curve448
import Crypto.Noise.Hash
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Hash.SHA512
import Crypto.Noise.Hash.BLAKE2s
import Crypto.Noise.Hash.BLAKE2b

data ServerOpts =
  ServerOpts { soLogFile     :: Maybe FilePath
             , soPort        :: String
             , soPSK         :: ScrubbedBytes
             , soLocal25519  :: KeyPair Curve25519
             , soRemote25519 :: PublicKey Curve25519
             , soLocal448    :: KeyPair Curve448
             , soRemote448   :: PublicKey Curve448
             }

data HandshakeType = NoiseNN
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

data CipherType :: * -> * where
  CTChaChaPoly1305 :: CipherType ChaChaPoly1305
  CTAESGCM         :: CipherType AESGCM

data SomeCipherType where
  WrapCipherType :: forall c. Cipher c => CipherType c -> SomeCipherType

data DHType :: * -> * where
  DTCurve25519 :: DHType Curve25519
  DTCurve448   :: DHType Curve448

data SomeDHType where
  WrapDHType :: forall d. DH d => DHType d -> SomeDHType

data HashType :: * -> * where
  HTSHA256  :: HashType SHA256
  HTSHA512  :: HashType SHA512
  HTBLAKE2s :: HashType BLAKE2s
  HTBLAKE2b :: HashType BLAKE2b

data SomeHashType where
  WrapHashType :: forall h. Hash h => HashType h -> SomeHashType

type Header = (Bool, HandshakeType, SomeCipherType, SomeDHType, SomeHashType)

instance Show HandshakeType where
  show NoiseNN = "NN"
  show NoiseKN = "KN"
  show NoiseNK = "NK"
  show NoiseKK = "KK"
  show NoiseNX = "NX"
  show NoiseKX = "KX"
  show NoiseXN = "XN"
  show NoiseIN = "IN"
  show NoiseXK = "XK"
  show NoiseIK = "IK"
  show NoiseXX = "XX"
  show NoiseIX = "IX"

instance Cipher c => Show (CipherType c) where
  show = unpack . convert . cipherName

instance DH d => Show (DHType d) where
  show = unpack . convert . dhName

instance Hash h => Show (HashType h) where
  show = unpack . convert . hashName
