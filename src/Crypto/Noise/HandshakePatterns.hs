----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.HandshakePatterns
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.HandshakePatterns
  ( -- * Functions
    noiseNNI,
    noiseNNR,
    noiseKNI,
    noiseKNR,
    noiseNKI,
    noiseNKR,
    noiseKKI,
    noiseKKR,
    noiseNEI,
    noiseNER,
    noiseKEI,
    noiseKER,
    noiseNXI,
    noiseNXR,
    noiseKXI,
    noiseKXR,
    noiseXNI,
    noiseXNR,
    noiseINI,
    noiseINR,
    noiseXKI,
    noiseXKR,
    noiseIKI,
    noiseIKR,
    noiseXEI,
    noiseXER,
    noiseIEI,
    noiseIER,
    noiseXXI,
    noiseXXR,
    noiseIXI,
    noiseIXR,
    noiseNI,
    noiseNR,
    noiseKI,
    noiseKR,
    noiseXI,
    noiseXR
  ) where

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Hash
import Crypto.Noise.Internal.HandshakeState
import Crypto.Noise.MessagePatterns

noiseNNI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNNI = ([noiseNNI1], [noiseNNI2])

noiseNNR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNNR = ([noiseNNR2], [noiseNNR1])

noiseKNI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKNI = ([noiseKNI1], [noiseKNI2])

noiseKNR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKNR = ([noiseKNR2], [noiseKNR1])

noiseNKI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNKI = ([noiseNKI1], [noiseNKI2])

noiseNKR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNKR = ([noiseNKR2], [noiseNKR1])

noiseKKI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKKI = ([noiseKKI1], [noiseKKI2])

noiseKKR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKKR = ([noiseKKR2], [noiseKKR1])

noiseNEI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNEI = ([noiseNEI1], [noiseNEI2])

noiseNER :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNER = ([noiseNER2], [noiseNER1])

noiseKEI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKEI = ([noiseKEI1], [noiseKEI2])

noiseKER :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKER = ([noiseKER2], [noiseKER1])

noiseNXI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNXI = ([noiseNXI1], [noiseNXI2])

noiseNXR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNXR = ([noiseNXR2], [noiseNXR1])

noiseKXI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKXI = ([noiseKXI1], [noiseKXI2])

noiseKXR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKXR = ([noiseKXR2], [noiseKXR1])

noiseXNI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXNI = ([noiseXNI1, noiseXNI3], [noiseXNI2])

noiseXNR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXNR = ([noiseXNR2], [noiseXNR1, noiseXNR3])

noiseINI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseINI = ([noiseINI1], [noiseINI2])

noiseINR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseINR = ([noiseINR2], [noiseINR1])

noiseXKI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXKI = ([noiseXKI1, noiseXKI3], [noiseXKI2])

noiseXKR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXKR = ([noiseXKR2], [noiseXKR1, noiseXKR3])

noiseIKI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseIKI = ([noiseIKI1], [noiseIKI2])

noiseIKR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseIKR = ([noiseIKR2], [noiseIKR1])

noiseXEI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXEI = ([noiseXEI1, noiseXEI3], [noiseXEI2])

noiseXER :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXER = ([noiseXER2], [noiseXER1, noiseXER3])

noiseIEI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseIEI = ([noiseIEI1], [noiseIEI2])

noiseIER :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseIER = ([noiseIER2], [noiseIER1])

noiseXXI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXXI = ([noiseXXI1, noiseXXI3], [noiseXXI2])

noiseXXR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXXR = ([noiseXXR2], [noiseXXR1, noiseXXR3])

noiseIXI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseIXI = ([noiseIXI1], [noiseIXI2])

noiseIXR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseIXR = ([noiseIXR2], [noiseIXR1])

noiseNI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNI = ([noiseNI1], [])

noiseNR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNR = ([], [noiseNR1])

noiseKI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKI = ([noiseKI1], [])

noiseKR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKR = ([], [noiseKR1])

noiseXI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXI = ([noiseXI1], [])

noiseXR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXR = ([], [noiseXR1])
