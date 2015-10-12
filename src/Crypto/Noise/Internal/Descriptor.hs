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
    noiseSNI2
  ) where

import Data.ByteString (ByteString)

import Crypto.Noise.Internal.HandshakeState
import Crypto.Noise.Cipher
import Crypto.Noise.Curve

--------------------------------------------------------------------------------
-- Noise_NN

noiseNNI1 :: (Cipher c, Curve d)
          => DescriptorIO c d ByteString
noiseNNI1 = tokenWE

noiseNNR1 :: (Cipher c, Curve d)
          => ByteString
          -> Descriptor c d ByteString
noiseNNR1 = tokenRE

noiseNNR2 :: (Cipher c, Curve d)
          => DescriptorIO c d ByteString
noiseNNR2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseNNI2 :: (Cipher c, Curve d)
          => ByteString
          -> Descriptor c d ByteString
noiseNNI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  return rest

--------------------------------------------------------------------------------
-- Noise_SN

noiseSNI0 :: (Cipher c, Curve d)
          => Descriptor c d ()
noiseSNI0 = tokenPreIS

noiseSNR0 :: (Cipher c, Curve d)
          => Descriptor c d ()
noiseSNR0 = tokenPreRS

noiseSNI1 :: (Cipher c, Curve d)
          => DescriptorIO c d ByteString
noiseSNI1 = tokenWE

noiseSNR1 :: (Cipher c, Curve d)
          => ByteString
          -> Descriptor c d ByteString
noiseSNR1 = tokenRE

noiseSNR2 :: (Cipher c, Curve d)
          => DescriptorIO c d ByteString
noiseSNR2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  return e

noiseSNI2 :: (Cipher c, Curve d)
          => ByteString
          -> Descriptor c d ByteString
noiseSNI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  return rest
