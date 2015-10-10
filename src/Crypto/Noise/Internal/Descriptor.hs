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
    noiseSNR0,
    noiseSNI1,
    noiseSNR1,
    noiseSNR2,
    noiseSNI2
  ) where

import Control.Monad.Identity
import Control.Monad.State

import Data.ByteString (ByteString)

import Crypto.Noise.Internal.HandshakeState
import Crypto.Noise.Cipher
import Crypto.Noise.Curve

--------------------------------------------------------------------------------
-- Noise_NN

noiseNNI1 :: (Cipher c, Curve d)
          => Descriptor c d IO ByteString
noiseNNI1 = tokenWE

noiseNNR1 :: (Cipher c, Curve d)
          => ByteString
          -> Descriptor c d Identity ByteString
noiseNNR1 = tokenRE

noiseNNR2 :: (Cipher c, Curve d)
          => Descriptor c d IO ByteString
noiseNNR2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseNNI2 :: (Cipher c, Curve d)
          => ByteString
          -> Descriptor c d Identity ByteString
noiseNNI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  return rest

--------------------------------------------------------------------------------
-- Noise_SN

noiseSNR0 :: (Cipher c, Curve d)
          => Descriptor c d Identity ()
noiseSNR0 = tokenPreS

noiseSNI1 :: (Cipher c, Curve d)
          => Descriptor c d IO ByteString
noiseSNI1 = tokenWE

noiseSNR1 :: (Cipher c, Curve d)
          => ByteString
          -> Descriptor c d Identity ByteString
noiseSNR1 = tokenRE

noiseSNR2 :: (MonadIO m, MonadHandshake m, Cipher c, Curve d)
          => Descriptor c d m ByteString
noiseSNR2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseSNI2 :: (Cipher c, Curve d)
          => ByteString
          -> Descriptor c d Identity ByteString
noiseSNI2 = undefined
