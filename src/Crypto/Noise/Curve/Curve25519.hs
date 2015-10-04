{-# LANGUAGE OverloadedStrings, TypeFamilies #-}

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
import Data.ByteArray (ScrubbedBytes)

import Crypto.Noise.Curve

data Curve25519

instance Curve Curve25519 where
  data PublicKey Curve25519 = PK25519  C.PublicKey
  data SecretKey Curve25519 = SK25519  C.SecretKey
  data DHOutput  Curve25519 = DHO25519 C.DhSecret

  curveName _ = "25519"
  curveLen _  = 32
  curveGenKey = _curveGenKey
  curveDH     = _curveDH

_curveGenKey :: IO (KeyPair Curve25519)
_curveGenKey = do
  r <- getEntropy 32 :: IO ScrubbedBytes
  let sk = either error id $ C.secretKey r
      pk = C.toPublic sk
  return (SK25519 sk, PK25519 pk)

_curveDH :: SecretKey Curve25519 -> PublicKey Curve25519 -> DHOutput Curve25519
_curveDH (SK25519 sk) (PK25519 pk) = DHO25519 $ C.dh pk sk
