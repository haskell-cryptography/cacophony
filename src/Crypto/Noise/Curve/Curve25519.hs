{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleInstances #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Curve.Curve25519
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Curve.Curve25519
  ( -- * Types
    Curve25519
  ) where

import Crypto.Random.Entropy
import qualified Crypto.PubKey.Curve25519 as C
import Data.ByteString (ByteString)

import Crypto.Noise.Curve
import Crypto.Noise.Types

data Curve25519

instance Curve Curve25519 where
  newtype PublicKey Curve25519 = PK25519 C.PublicKey
  newtype SecretKey Curve25519 = SK25519 C.SecretKey

  curveName _     = convert ("25519" :: ByteString)
  curveLen _      = 32
  curveGenKey     = genKey
  curveDH         = dh
  curvePubToBytes = pubToBytes
  curveBytesToPub = bytesToPub

genKey :: IO (KeyPair Curve25519)
genKey = do
  r <- getEntropy 32 :: IO ScrubbedBytes
  let sk = either error id $ C.secretKey r
      pk = C.toPublic sk
  return (SK25519 sk, PK25519 pk)

dh :: SecretKey Curve25519 -> PublicKey Curve25519 -> ScrubbedBytes
dh (SK25519 sk) (PK25519 pk) = convert $ C.dh pk sk

pubToBytes :: PublicKey Curve25519 -> ScrubbedBytes
pubToBytes (PK25519 pk) = convert pk

bytesToPub :: ScrubbedBytes -> PublicKey Curve25519
bytesToPub b = PK25519 $ either error id $ C.publicKey b
