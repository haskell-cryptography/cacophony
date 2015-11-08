----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.MessagePatterns
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
--
-- This module contains all of the message patterns for all the handshakes
-- specified in the protocol. The first two characters of the name
-- represent the handshake the pattern belongs to (NN, KN, NK, etc). The
-- next character represents whether the pattern is intended to be used
-- by the __I__nitiator or the __R__esponder. Finally, the number indicates
-- the step of the handshake in which the pattern is intended to be used.
-- Regular handshake steps begin at 1, but patterns for pre-messages are
-- numbered 0. The patterns for pre-messages are intended to be passed
-- to the 'handshakeState' function. The (de-)serialization of pre-messages
-- is beyond the scope of this library, but public keys can be
-- imported/exported using the 'curveBytesToPub' and 'curvePubToBytes'
-- functions.
module Crypto.Noise.MessagePatterns
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
    noiseKEI2,
     -- * Noise_NX
    noiseNXI1,
    noiseNXR1,
    noiseNXR2,
    noiseNXI2,
    -- * Noise_KX
    noiseKXI0,
    noiseKXR0,
    noiseKXI1,
    noiseKXR1,
    noiseKXR2,
    noiseKXI2,
    -- ** Noise_XN
    noiseXNI1,
    noiseXNR1,
    noiseXNR2,
    noiseXNI2,
    noiseXNI3,
    noiseXNR3,
    -- * Noise_IN
    noiseINI1,
    noiseINR1,
    noiseINR2,
    noiseINI2,
    -- ** Noise_XK
    noiseXKI0,
    noiseXKR0,
    noiseXKI1,
    noiseXKR1,
    noiseXKR2,
    noiseXKI2,
    noiseXKI3,
    noiseXKR3,
    -- * Noise_IK
    noiseIKI0,
    noiseIKR0,
    noiseIKI1,
    noiseIKR1,
    noiseIKR2,
    noiseIKI2,
    -- ** Noise_XE
    noiseXEI0,
    noiseXER0,
    noiseXEI1,
    noiseXER1,
    noiseXER2,
    noiseXEI2,
    noiseXEI3,
    noiseXER3,
    -- * Noise_IE
    noiseIEI0,
    noiseIER0,
    noiseIEI1,
    noiseIER1,
    noiseIER2,
    noiseIEI2,
    -- ** Noise_XX
    noiseXXI1,
    noiseXXR1,
    noiseXXR2,
    noiseXXI2,
    noiseXXI3,
    noiseXXR3,
    -- * Noise_IX
    noiseIXI1,
    noiseIXR1,
    noiseIXR2,
    noiseIXI2,
    -- * Noise_N
    noiseNI0,
    noiseNR0,
    noiseNI1,
    noiseNR1,
    -- * Noise_K
    noiseKI0,
    noiseKR0,
    noiseKI1,
    noiseKR1,
     -- * Noise_X
    noiseXI0,
    noiseXR0,
    noiseXI1,
    noiseXR1
  ) where

import Control.Monad ((>=>))
import Data.ByteString (ByteString, append)

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Hash
import Crypto.Noise.Internal.HandshakeState

--------------------------------------------------------------------------------
-- Noise_NN

noiseNNI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseNNI1 = tokenWE

noiseNNR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseNNR1 = tokenRE

noiseNNR2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseNNR2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseNNI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseNNI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  return rest

--------------------------------------------------------------------------------
-- Noise_KN

noiseKNI0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseKNI0 = tokenPreLS

noiseKNR0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseKNR0 = tokenPreRS

noiseKNI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseKNI1 = tokenWE

noiseKNR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseKNR1 = tokenRE

noiseKNR2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseKNR2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  return e

noiseKNI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseKNI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  return rest

--------------------------------------------------------------------------------
-- Noise_NK

noiseNKI0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseNKI0 = tokenPreRS

noiseNKR0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseNKR0 = tokenPreLS

noiseNKI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseNKI1 = do
  e <- tokenWE
  tokenDHES
  return e

noiseNKR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseNKR1 buf = do
  rest <- tokenRE buf
  tokenDHSE
  return rest

noiseNKR2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseNKR2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseNKI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseNKI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  return rest

--------------------------------------------------------------------------------
-- Noise_KK

noiseKKI0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseKKI0 = do
  tokenPreLS
  tokenPreRS

noiseKKR0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseKKR0 = do
  tokenPreRS
  tokenPreLS

noiseKKI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseKKI1 = do
  e <- tokenWE
  tokenDHES
  tokenDHSS
  return e

noiseKKR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseKKR1 buf = do
  rest <- tokenRE buf
  tokenDHSE
  tokenDHSS
  return rest

noiseKKR2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseKKR2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  return e

noiseKKI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseKKI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  return rest

--------------------------------------------------------------------------------
-- Noise_NE

noiseNEI0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseNEI0 = do
  tokenPreRS
  tokenPreRE

noiseNER0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseNER0 = do
  tokenPreLS
  tokenPreLE

noiseNEI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseNEI1 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  return e

noiseNER1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseNER1 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  return rest

noiseNER2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseNER2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseNEI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseNEI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  return rest

--------------------------------------------------------------------------------
-- Noise_KE

noiseKEI0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseKEI0 = do
  tokenPreRS
  tokenPreRE
  tokenPreLS

noiseKER0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseKER0 = do
  tokenPreLS
  tokenPreLE
  tokenPreRS

noiseKEI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseKEI1 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  tokenDHSE
  return e

noiseKER1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseKER1 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  tokenDHES
  return rest

noiseKER2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseKER2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHSE
  return e

noiseKEI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseKEI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHES
  return rest

--------------------------------------------------------------------------------
-- Noise_NX

noiseNXI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseNXI1 = tokenWE

noiseNXR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseNXR1 = tokenRE

noiseNXR2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseNXR2 = do
  e <- tokenWE
  tokenDHEE
  s <- tokenWS
  tokenDHSE
  return $ e `append` s

noiseNXI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseNXI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  rest' <- tokenRS rest
  tokenDHES
  return rest'

--------------------------------------------------------------------------------
-- Noise_KX

noiseKXI0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseKXI0 = tokenPreLS

noiseKXR0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseKXR0 = tokenPreRS

noiseKXI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseKXI1 = tokenWE

noiseKXR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseKXR1 = tokenRE

noiseKXR2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseKXR2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  s <- tokenWS
  tokenDHSE
  return $ e `append` s

noiseKXI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseKXI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  rest' <- tokenRS rest
  tokenDHES
  return rest'

--------------------------------------------------------------------------------
-- Noise_XN

noiseXNI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXNI1 = tokenWE

noiseXNR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXNR1 = tokenRE

noiseXNR2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXNR2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseXNI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXNI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  return rest

noiseXNI3 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXNI3 = do
  s <- tokenWS
  tokenDHSE
  return s

noiseXNR3 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXNR3 buf = do
  rest <- tokenRS buf
  tokenDHES
  return rest

--------------------------------------------------------------------------------
-- Noise_IN

noiseINI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseINI1 = do
  s <- tokenWS
  e <- tokenWE
  return $ s `append` e

noiseINR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseINR1 buf = do
  rest  <- tokenRS buf
  tokenRE rest

noiseINR2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseINR2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  return e

noiseINI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseINI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  return rest

--------------------------------------------------------------------------------
-- Noise_XK

noiseXKI0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseXKI0 = tokenPreRS

noiseXKR0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseXKR0 = tokenPreLS

noiseXKI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXKI1 = do
  e <- tokenWE
  tokenDHES
  return e

noiseXKR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXKR1 buf = do
  rest <- tokenRE buf
  tokenDHSE
  return rest

noiseXKR2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXKR2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseXKI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXKI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  return rest

noiseXKI3 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXKI3 = do
  s <- tokenWS
  tokenDHSE
  return s

noiseXKR3 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXKR3 buf = do
  rest <- tokenRS buf
  tokenDHES
  return rest

--------------------------------------------------------------------------------
-- Noise_IK

noiseIKI0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseIKI0 = tokenPreRS

noiseIKR0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseIKR0 = tokenPreLS

noiseIKI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseIKI1 = do
  e <- tokenWE
  tokenDHES
  s <- tokenWS
  tokenDHSS
  return $ e `append` s

noiseIKR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseIKR1 buf = do
  rest <- tokenRE buf
  tokenDHSE
  rest' <- tokenRS rest
  tokenDHSS
  return rest'

noiseIKR2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseIKR2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  return e

noiseIKI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseIKI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  return rest

--------------------------------------------------------------------------------
-- Noise_XE

noiseXEI0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseXEI0 = do
  tokenPreRS
  tokenPreRE

noiseXER0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseXER0 = do
  tokenPreLS
  tokenPreLE

noiseXEI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXEI1 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  return e

noiseXER1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXER1 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  return rest

noiseXER2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXER2 = do
  e <- tokenWE
  tokenDHEE
  return e

noiseXEI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXEI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  return rest

noiseXEI3 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXEI3 = do
  s <- tokenWS
  tokenDHSE
  return s

noiseXER3 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXER3 buf = do
  rest <- tokenRS buf
  tokenDHES
  return rest

--------------------------------------------------------------------------------
-- Noise_IE

noiseIEI0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseIEI0 = do
  tokenPreRS
  tokenPreRE

noiseIER0 :: (Cipher c, Curve d, Hash h)
          => MessagePattern c d h ()
noiseIER0 = do
  tokenPreLS
  tokenPreLE

noiseIEI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseIEI1 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  s <- tokenWS
  tokenDHSE
  return $ e `append` s

noiseIER1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseIER1 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  rest' <- tokenRS rest
  tokenDHES
  return rest'

noiseIER2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseIER2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  return e

noiseIEI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseIEI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  return rest

--------------------------------------------------------------------------------
-- Noise_XX

noiseXXI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXXI1 = tokenWE

noiseXXR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXXR1 = tokenRE

noiseXXR2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXXR2 = do
  e <- tokenWE
  tokenDHEE
  s <- tokenWS
  tokenDHSE
  return $ e `append` s

noiseXXI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXXI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  rest' <- tokenRS rest
  tokenDHES
  return rest'

noiseXXI3 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXXI3 = do
  s <- tokenWS
  tokenDHSE
  return s

noiseXXR3 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXXR3 buf = do
  rest <- tokenRS buf
  tokenDHES
  return rest

--------------------------------------------------------------------------------
-- Noise_IX

noiseIXI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseIXI1 = do
  s <- tokenWS
  e <- tokenWE
  return $ s `append` e

noiseIXR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseIXR1 = tokenRS >=> tokenRE

noiseIXR2 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseIXR2 = do
  e <- tokenWE
  tokenDHEE
  tokenDHES
  s <- tokenWS
  tokenDHSE
  return $ e `append` s

noiseIXI2 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseIXI2 buf = do
  rest <- tokenRE buf
  tokenDHEE
  tokenDHSE
  rest' <- tokenRS rest
  tokenDHES
  return rest'

--------------------------------------------------------------------------------
-- Noise_N

noiseNI0 :: (Cipher c, Curve d, Hash h)
         => MessagePattern c d h ()
noiseNI0 = tokenPreRS

noiseNR0 :: (Cipher c, Curve d, Hash h)
         => MessagePattern c d h ()
noiseNR0 = tokenPreLS

noiseNI1 :: (Cipher c, Curve d, Hash h)
        => MessagePatternIO c d h ByteString
noiseNI1 = do
  e <- tokenWE
  tokenDHES
  return e

noiseNR1 :: (Cipher c, Curve d, Hash h)
        => ByteString
        -> MessagePattern c d h ByteString
noiseNR1 buf = do
  rest <- tokenRE buf
  tokenDHSE
  return rest

--------------------------------------------------------------------------------
-- Noise_K

noiseKI0 :: (Cipher c, Curve d, Hash h)
         => MessagePattern c d h ()
noiseKI0 = do
  tokenPreLS
  tokenPreRS

noiseKR0 :: (Cipher c, Curve d, Hash h)
         => MessagePattern c d h ()
noiseKR0 = do
  tokenPreRS
  tokenPreLS

noiseKI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseKI1 = do
  e <- tokenWE
  tokenDHES
  tokenDHSS
  return e

noiseKR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseKR1 buf = do
  rest <- tokenRE buf
  tokenDHSE
  tokenDHSS
  return rest

--------------------------------------------------------------------------------
-- Noise_X

noiseXI0 :: (Cipher c, Curve d, Hash h)
         => MessagePattern c d h ()
noiseXI0 = tokenPreRS

noiseXR0 :: (Cipher c, Curve d, Hash h)
         => MessagePattern c d h ()
noiseXR0 = tokenPreLS

noiseXI1 :: (Cipher c, Curve d, Hash h)
          => MessagePatternIO c d h ByteString
noiseXI1 = do
  e <- tokenWE
  tokenDHES
  s <- tokenWS
  tokenDHSS
  return $ e `append` s

noiseXR1 :: (Cipher c, Curve d, Hash h)
          => ByteString
          -> MessagePattern c d h ByteString
noiseXR1 buf = do
  rest <- tokenRE buf
  tokenDHSE
  rest' <- tokenRS rest
  tokenDHSS
  return rest'
