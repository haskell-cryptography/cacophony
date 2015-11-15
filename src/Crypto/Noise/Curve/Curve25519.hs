{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleInstances #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Curve.Curve25519
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Curve.Curve25519
  ( -- * Types
    Curve25519
  ) where

import Crypto.Error          (throwCryptoError)
import Crypto.Random.Entropy (getEntropy)
import qualified Crypto.PubKey.Curve25519 as C

import Crypto.Noise.Curve
import Crypto.Noise.Types

-- | Represents curve25519 curve.
data Curve25519

instance Curve Curve25519 where
  newtype PublicKey Curve25519 = PK25519 C.PublicKey
  newtype SecretKey Curve25519 = SK25519 C.SecretKey

  curveName   _    = bsToSB' "25519"
  curveLength _    = 32
  curveGenKey      = genKey
  curveDH          = dh
  curvePubToBytes  = pubToBytes
  curveBytesToPub  = bytesToPub
  curveSecToBytes  = secToBytes
  curveBytesToPair = bytesToPair

genKey :: IO (KeyPair Curve25519)
genKey = do
  r <- getEntropy 32 :: IO ScrubbedBytes
  let sk = throwCryptoError . C.secretKey $ r
      pk = C.toPublic sk
  return (SK25519 sk, PK25519 pk)

dh :: SecretKey Curve25519 -> PublicKey Curve25519 -> ScrubbedBytes
dh (SK25519 sk) (PK25519 pk) = convert $ C.dh pk sk

pubToBytes :: PublicKey Curve25519 -> ScrubbedBytes
pubToBytes (PK25519 pk) = convert pk

bytesToPub :: ScrubbedBytes -> PublicKey Curve25519
bytesToPub b = PK25519 . throwCryptoError . C.publicKey $ b

secToBytes :: SecretKey Curve25519 -> ScrubbedBytes
secToBytes (SK25519 sk) = convert sk

bytesToPair :: ScrubbedBytes -> KeyPair Curve25519
bytesToPair bs = (SK25519 sk, PK25519 pk)
  where
    sk = throwCryptoError . C.secretKey $ bs
    pk = C.toPublic sk
