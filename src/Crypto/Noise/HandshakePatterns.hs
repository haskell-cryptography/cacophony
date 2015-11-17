{-# LANGUAGE OverloadedStrings #-}
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
noiseNNI = HandshakePattern "NN" Nothing [noiseNNI1] [noiseNNI2]

noiseNNR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNNR = HandshakePattern "NN" Nothing [noiseNNR2] [noiseNNR1]

noiseKNI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKNI = HandshakePattern "KN" (Just noiseKNI0) [noiseKNI1] [noiseKNI2]

noiseKNR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKNR = HandshakePattern "KN" (Just noiseKNR0) [noiseKNR2] [noiseKNR1]

noiseNKI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNKI = HandshakePattern "NK" (Just noiseNKI0) [noiseNKI1] [noiseNKI2]

noiseNKR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNKR = HandshakePattern "NK" (Just noiseNKR0) [noiseNKR2] [noiseNKR1]

noiseKKI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKKI = HandshakePattern "KK" (Just noiseKKI0) [noiseKKI1] [noiseKKI2]

noiseKKR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKKR = HandshakePattern "KK" (Just noiseKKR0) [noiseKKR2] [noiseKKR1]

noiseNEI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNEI = HandshakePattern "NE" (Just noiseNEI0) [noiseNEI1] [noiseNEI2]

noiseNER :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNER = HandshakePattern "NE" (Just noiseNER0) [noiseNER2] [noiseNER1]

noiseKEI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKEI = HandshakePattern "KE" (Just noiseKEI0) [noiseKEI1] [noiseKEI2]

noiseKER :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKER = HandshakePattern "KE" (Just noiseKER0) [noiseKER2] [noiseKER1]

noiseNXI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNXI = HandshakePattern "NX" Nothing [noiseNXI1] [noiseNXI2]

noiseNXR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNXR = HandshakePattern "NX" Nothing [noiseNXR2] [noiseNXR1]

noiseKXI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKXI = HandshakePattern "KX" (Just noiseKXI0) [noiseKXI1] [noiseKXI2]

noiseKXR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKXR = HandshakePattern "KX" (Just noiseKXR0) [noiseKXR2] [noiseKXR1]

noiseXNI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXNI = HandshakePattern "XN" Nothing [noiseXNI1, noiseXNI3] [noiseXNI2]

noiseXNR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXNR = HandshakePattern "XN" Nothing [noiseXNR2] [noiseXNR1, noiseXNR3]

noiseINI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseINI = HandshakePattern "IN" Nothing[noiseINI1] [noiseINI2]

noiseINR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseINR = HandshakePattern "IN" Nothing [noiseINR2] [noiseINR1]

noiseXKI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXKI = HandshakePattern "XK" (Just noiseXKI0) [noiseXKI1, noiseXKI3] [noiseXKI2]

noiseXKR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXKR = HandshakePattern "XK" (Just noiseXKR0) [noiseXKR2] [noiseXKR1, noiseXKR3]

noiseIKI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseIKI = HandshakePattern "IK" (Just noiseIKI0) [noiseIKI1] [noiseIKI2]

noiseIKR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseIKR = HandshakePattern "IK" (Just noiseIKR0) [noiseIKR2] [noiseIKR1]

noiseXEI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXEI = HandshakePattern "XE" (Just noiseXEI0) [noiseXEI1, noiseXEI3] [noiseXEI2]

noiseXER :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXER = HandshakePattern "XE" (Just noiseXER0) [noiseXER2] [noiseXER1, noiseXER3]

noiseIEI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseIEI = HandshakePattern "IE" (Just noiseIEI0) [noiseIEI1] [noiseIEI2]

noiseIER :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseIER = HandshakePattern "IE" (Just noiseIER0) [noiseIER2] [noiseIER1]

noiseXXI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXXI = HandshakePattern "XX" Nothing [noiseXXI1, noiseXXI3] [noiseXXI2]

noiseXXR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXXR = HandshakePattern "XX" Nothing [noiseXXR2] [noiseXXR1, noiseXXR3]

noiseIXI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseIXI = HandshakePattern "IX" Nothing [noiseIXI1] [noiseIXI2]

noiseIXR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseIXR = HandshakePattern "IX" Nothing [noiseIXR2] [noiseIXR1]

noiseNI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNI = HandshakePattern "N" (Just noiseNI0) [noiseNI1] []

noiseNR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseNR = HandshakePattern "N" (Just noiseNR0) [] [noiseNR1]

noiseKI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKI = HandshakePattern "K" (Just noiseKI0) [noiseKI1] []

noiseKR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseKR = HandshakePattern "K" (Just noiseKR0) [] [noiseKR1]

noiseXI :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXI = HandshakePattern "X" (Just noiseXI0) [noiseXI1] []

noiseXR :: (Cipher c, Curve d, Hash h) => HandshakePattern c d h
noiseXR = HandshakePattern "X" (Just noiseXR0) [] [noiseXR1]
