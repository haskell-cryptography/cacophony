----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.Descriptor
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.Descriptor
  ( -- * Types
    Descriptor,
    -- * Functions
    noiseNNI1,
    noiseNNR1,
    noiseNNR2,
    noiseNNI2
  ) where

import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B (splitAt)
import Data.Functor.Identity (Identity, runIdentity)
import Data.Maybe (fromJust)

import Crypto.Noise.Internal.SymmetricHandshakeState
import Crypto.Noise.Internal.HandshakeState
import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Types

tokenWE :: (Cipher c, Curve d)
        => Descriptor c d IO ByteString
tokenWE = do
  kp <- liftIO curveGenKey
  hs <- get
  let pk         = snd . curveKeyBytes $ kp
      shs        = hssSymmetricHandshake hs
      (ct, shs') = encryptAndHash shs (Plaintext (convert pk))
  put $ hs { hssLocalEphemeralKey = Just kp
           , hssSymmetricHandshake = shs'
           }
  return . convert $ ct

tokenRE :: (Cipher c, Curve d)
        => ByteString
        -> Descriptor c d Identity ByteString
tokenRE buf = do
  hs <- get
  let hasKey    = shsHasKey . hssSymmetricHandshake $ hs
      (b, rest) = B.splitAt (d hasKey) buf
      ct        = cipherBytesToText . convert $ b
      shs       = hssSymmetricHandshake hs
      (Plaintext pt, shs') = decryptAndHash shs ct
  put $ hs { hssRemoteEphemeralKey = Just (curveBytesToPub pt)
           , hssSymmetricHandshake = shs'
           }
  return rest
  where
    d hk
      | hk        = 32 + 16
      | otherwise = 32 -- this should call curveLen!

tokenDH :: (Cipher c, Curve d)
        => KeyPair d
        -> PublicKey d
        -> Descriptor c d Identity ()
tokenDH (sk, _) rpk = do
  hs <- get
  let shs  = hssSymmetricHandshake hs
      dh   = curveDH sk rpk
      shs' = mixKey shs dh
  put $ hs { hssSymmetricHandshake = shs' }

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
  hs <- get
  let kp       = fromJust $ hssLocalEphemeralKey hs
      rpk      = fromJust $ hssRemoteEphemeralKey hs
      (_, hs') = runIdentity $ runDescriptor (tokenDH kp rpk) hs
  put hs'
  return e

noiseNNI2 :: (Cipher c, Curve d)
          => ByteString
          -> Descriptor c d Identity ByteString
noiseNNI2 buf = do
  rest <- tokenRE buf
  hs <- get
  let kp  = fromJust $ hssLocalEphemeralKey hs
      rpk = fromJust $ hssRemoteEphemeralKey hs
  tokenDH kp rpk
  return rest
