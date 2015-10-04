{-# LANGUAGE OverloadedStrings, TypeFamilies #-}

----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Curve
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Curve.Curve25519
  ( Curve25519,
    curve25519,
    -- * Type families
    PublicKey(..),
    SecretKey(..),
    DHOutput(..),
    -- * Types
    KeyPair,
  ) where

import qualified Crypto.PubKey.Curve25519 as C

import Crypto.Noise.Curve

data Curve25519

data instance PublicKey Curve25519 = PublicKey C.PublicKey
data instance SecretKey Curve25519 = SecretKey C.SecretKey
data instance DHOutput  Curve25519 = DHOutput  C.DhSecret

curve25519 :: Curve Curve25519
curve25519 =
  Curve { curveName   = "25519"
        , curveLen    = 32
        , curveGenKey = _curveGenKey
        , curveDH     = _curveDH
        }

_curveGenKey :: IO (KeyPair c)
_curveGenKey = undefined

_curveDH :: SecretKey c -> PublicKey c -> DHOutput c
_curveDH = undefined
