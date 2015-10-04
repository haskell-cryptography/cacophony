{-# LANGUAGE TypeFamilies #-}

----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Curve
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Curve
  ( -- * Type families
    PublicKey,
    SecretKey,
    DHOutput,
    -- * Types
    KeyPair,
    Curve(..)
  ) where

import Data.ByteString (ByteString)

data family PublicKey c :: *
data family SecretKey c :: *
data family DHOutput  c :: *

type KeyPair c = (PublicKey c, SecretKey c)

data Curve c =
  Curve {
    curveName   :: ByteString,
    curveLen    :: Int,
    curveGenKey :: IO (KeyPair c),
    curveDH     :: SecretKey c -> PublicKey c -> DHOutput c
  }
