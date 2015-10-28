----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.Descriptor
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.Descriptor
  ( -- * Functions
    -- ** Noise_NN
    noiseNNI1,
    noiseNNR1,
    noiseNNR2,
    noiseNNI2,
    -- ** Noise_KN
    noiseKNI0,
    noiseKNR0,
    noiseKNI1,
    noiseKNR1,
    noiseKNR2,
    noiseKNI2,
    -- * Noise_NK
    noiseNKI0,
    noiseNKR0,
    noiseNKI1,
    noiseNKR1,
    noiseNKR2,
    noiseNKI2
  ) where

import Data.ByteString (ByteString)

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Hash
import Crypto.Noise.Internal.HandshakeState

--------------------------------------------------------------------------------
-- Noise_NN

noiseNNI1 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseNNI1 = tokenWE

noiseNNR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseNNR1 = tokenRE

noiseNNR2 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseNNR2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseNNI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseNNI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  return rest

--------------------------------------------------------------------------------
-- Noise_KN

noiseKNI0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseKNI0 = tokenPreWS

noiseKNR0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseKNR0 = tokenPreRS

noiseKNI1 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseKNI1 = tokenWE

noiseKNR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseKNR1 = tokenRE

noiseKNR2 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseKNR2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  return e

noiseKNI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseKNI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  return rest

--------------------------------------------------------------------------------
-- Noise_NK

noiseNKI0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseNKI0 = tokenPreRS

noiseNKR0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseNKR0 = tokenPreWS

noiseNKI1 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseNKI1 = do
  e <- tokenWE
  tokenDHES
  return e

noiseNKR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseNKR1 buf = do
  rest <- tokenRE buf
  tokenDHSE
  return rest

noiseNKR2 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseNKR2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseNKI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseNKI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  return rest
