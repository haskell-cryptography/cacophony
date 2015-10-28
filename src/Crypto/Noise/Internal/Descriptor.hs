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
    noiseNKI2,
    -- * Noise_KK
    noiseKKI0,
    noiseKKR0,
    noiseKKI1,
    noiseKKR1,
    noiseKKR2,
    noiseKKI2,
    -- * Noise_NE
    noiseNEI0,
    noiseNER0,
    noiseNEI1,
    noiseNER1,
    noiseNER2,
    noiseNEI2,
    -- * Noise_KE
    noiseKEI0,
    noiseKER0,
    noiseKEI1,
    noiseKER1,
    noiseKER2,
    noiseKEI2
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
noiseKNI0 = tokenPreLS

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
noiseNKR0 = tokenPreLS

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

--------------------------------------------------------------------------------
-- Noise_KK

noiseKKI0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseKKI0 = do
  tokenPreRS
  tokenPreLS

noiseKKR0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseKKR0 = do
  tokenPreLS
  tokenPreRS

noiseKKI1 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseKKI1 = do
  e <- tokenWE
  tokenDHES
  tokenDHSS
  return e

noiseKKR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseKKR1 buf = do
  rest <- tokenRE buf
  tokenDHSE
  tokenDHSS
  return rest

noiseKKR2 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseKKR2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  return e

noiseKKI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseKKI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  return rest

--------------------------------------------------------------------------------
-- Noise_NE

noiseNEI0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseNEI0 = do
  tokenPreRS
  tokenPreRE

noiseNER0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseNER0 = do
  tokenPreLS
  tokenPreLE

noiseNEI1 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseNEI1 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  return e

noiseNER1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseNER1 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  return rest

noiseNER2 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseNER2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseNEI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseNEI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  return rest

--------------------------------------------------------------------------------
-- Noise_KE

noiseKEI0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseKEI0 = do
  tokenPreRS
  tokenPreRE
  tokenPreLS

noiseKER0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseKER0 = do
  tokenPreLS
  tokenPreLE
  tokenPreRS

noiseKEI1 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseKEI1 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  tokenDHSE
  return e

noiseKER1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseKER1 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  tokenDHES
  return rest

noiseKER2 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseKER2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHSE
  return e

noiseKEI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseKEI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHES
  return rest
