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
    -- ** Noise_SN
    noiseSNI0,
    noiseSNR0,
    noiseSNI1,
    noiseSNR1,
    noiseSNR2,
    noiseSNI2,
    -- * Noise_NS
    noiseNSI0,
    noiseNSR0,
    noiseNSI1,
    noiseNSR1,
    noiseNSR2,
    noiseNSI2
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
-- Noise_SN

noiseSNI0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseSNI0 = tokenPreWS

noiseSNR0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseSNR0 = tokenPreRS

noiseSNI1 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseSNI1 = tokenWE

noiseSNR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseSNR1 = tokenRE

noiseSNR2 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseSNR2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  return e

noiseSNI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseSNI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  return rest

--------------------------------------------------------------------------------
-- Noise_NS

noiseNSI0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseNSI0 = tokenPreRS

noiseNSR0 :: (Cipher c, Curve d, Hash h)
          => Descriptor c d h ()
noiseNSR0 = tokenPreWS

noiseNSI1 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseNSI1 = do
  e <- tokenWE
  tokenDHES
  return e

noiseNSR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseNSR1 buf = do
  rest <- tokenRE buf
  tokenDHSE
  return rest

noiseNSR2 :: (Cipher c, Curve d, Hash h)
          => DescriptorIO c d h ByteString
noiseNSR2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseNSI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> Descriptor c d h ByteString
noiseNSI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  return rest
