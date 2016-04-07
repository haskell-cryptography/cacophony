{-# LANGUAGE RankNTypes, KindSignatures, GADTs #-}
module Types where

import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Cipher.AESGCM
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Curve.Curve448
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

data CipherType :: * -> * where
  CTChaChaPoly1305 :: CipherType ChaChaPoly1305
  CTAESGCM         :: CipherType AESGCM

data SomeCipherType where
  WrapCipherType :: forall c. Cipher c => CipherType c -> SomeCipherType

data CurveType :: * -> * where
  CTCurve25519 :: CurveType Curve25519
  CTCurve448   :: CurveType Curve448

data SomeCurveType where
  WrapCurveType :: forall d. Curve d => CurveType d -> SomeCurveType

data HashType :: * -> * where
  HTSHA256  :: HashType SHA256
  HTSHA512  :: HashType SHA512
  HTBLAKE2s :: HashType BLAKE2s
  HTBLAKE2b :: HashType BLAKE2b

data SomeHashType where
  WrapHashType :: forall h. Hash h => HashType h -> SomeHashType
