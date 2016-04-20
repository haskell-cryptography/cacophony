{-# LANGUAGE OverloadedStrings, RankNTypes, KindSignatures, GADTs #-}
module Types where

import Data.Aeson

import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Cipher.AESGCM
import Crypto.Noise.DH
import Crypto.Noise.DH.Curve25519
import Crypto.Noise.DH.Curve448
import Crypto.Noise.HandshakePatterns
import Crypto.Noise.Hash
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Hash.SHA512
import Crypto.Noise.Hash.BLAKE2s
import Crypto.Noise.Hash.BLAKE2b

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
                   | NoiseXR
                   | NoiseN
                   | NoiseK
                   | NoiseX
                   deriving Eq

data CipherType :: * -> * where
  CTChaChaPoly1305 :: CipherType ChaChaPoly1305
  CTAESGCM         :: CipherType AESGCM

data SomeCipherType where
  WrapCipherType :: forall c. Cipher c => CipherType c -> SomeCipherType

instance ToJSON SomeCipherType where
  toJSON (WrapCipherType CTChaChaPoly1305) = "ChaChaPoly"
  toJSON (WrapCipherType CTAESGCM) = "AESGCM"

instance Cipher c => Show (CipherType c) where
  show CTChaChaPoly1305 = "ChaChaPoly"
  show CTAESGCM = "AESGCM"

data DHType :: * -> * where
  DTCurve25519 :: DHType Curve25519
  DTCurve448   :: DHType Curve448

data SomeDHType where
  WrapDHType :: forall d. DH d => DHType d -> SomeDHType

instance ToJSON SomeDHType where
  toJSON (WrapDHType DTCurve25519) = "25519"
  toJSON (WrapDHType DTCurve448)   = "448"

instance DH d => Show (DHType d) where
  show DTCurve25519 = "25519"
  show DTCurve448 = "448"

data HashType :: * -> * where
  HTSHA256  :: HashType SHA256
  HTSHA512  :: HashType SHA512
  HTBLAKE2s :: HashType BLAKE2s
  HTBLAKE2b :: HashType BLAKE2b

data SomeHashType where
  WrapHashType :: forall h. Hash h => HashType h -> SomeHashType

hsTypeToPattern :: HandshakeType
                -> HandshakePattern
hsTypeToPattern NoiseNN = noiseNN
hsTypeToPattern NoiseKN = noiseKN
hsTypeToPattern NoiseNK = noiseNK
hsTypeToPattern NoiseKK = noiseKK
hsTypeToPattern NoiseNX = noiseNX
hsTypeToPattern NoiseKX = noiseKX
hsTypeToPattern NoiseXN = noiseXN
hsTypeToPattern NoiseIN = noiseIN
hsTypeToPattern NoiseXK = noiseXK
hsTypeToPattern NoiseIK = noiseIK
hsTypeToPattern NoiseXX = noiseXX
hsTypeToPattern NoiseIX = noiseIX
hsTypeToPattern NoiseXR = noiseXR
hsTypeToPattern NoiseN  = noiseN
hsTypeToPattern NoiseK  = noiseK
hsTypeToPattern NoiseX  = noiseX

instance ToJSON SomeHashType where
  toJSON (WrapHashType HTSHA256) = "SHA256"
  toJSON (WrapHashType HTSHA512) = "SHA512"
  toJSON (WrapHashType HTBLAKE2s) = "BLAKE2s"
  toJSON (WrapHashType HTBLAKE2b) = "BLAKE2b"

instance Hash h => Show (HashType h) where
  show HTSHA256  = "SHA256"
  show HTSHA512  = "SHA512"
  show HTBLAKE2s = "BLAKE2s"
  show HTBLAKE2b = "BLAKE2b"

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
  show NoiseXR = "XR"
  show NoiseN  = "N"
  show NoiseK  = "K"
  show NoiseX  = "X"
