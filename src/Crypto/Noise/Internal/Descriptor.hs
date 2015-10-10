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

--------------------------------------------------------------------------------
-- TOKENS

tokenWE :: (Cipher c, Curve d)
        => Descriptor c d IO ByteString
tokenWE = do
  kp@(_, pk) <- liftIO curveGenKey
  hs <- get
  let pk'        = curvePubToBytes pk
      shs        = hssSymmetricHandshake hs
      (ct, shs') = encryptAndHash (Plaintext pk') shs
  put $ hs { hssLocalEphemeralKey = Just kp
           , hssSymmetricHandshake = shs'
           }
  return . convert $ ct

tokenR :: (Cipher c, Curve d)
       => ByteString
       -> Bool
       -> Descriptor c d Identity ByteString
tokenR buf updateEphemeral = do
  hs <- get
  let hasKey    = shsHasKey . hssSymmetricHandshake $ hs
      (b, rest) = B.splitAt (d hasKey) buf
      ct        = cipherBytesToText . convert $ b
      shs       = hssSymmetricHandshake hs
      (Plaintext pt, shs') = decryptAndHash ct shs
      hs'
        | updateEphemeral = hs { hssRemoteEphemeralKey = Just (curveBytesToPub pt)
                               , hssSymmetricHandshake = shs'
                               }
        | otherwise       = hs { hssRemoteStaticKey = Just (curveBytesToPub pt)
                               , hssSymmetricHandshake = shs'
                               }
  put hs'
  return rest
  where
    d hk
      | hk        = 32 + 16
      | otherwise = 32 -- this should call curveLen!

tokenRE :: (Cipher c, Curve d)
        => ByteString
        -> Descriptor c d Identity ByteString
tokenRE buf = tokenR buf True

tokenWS :: (Cipher c, Curve d)
        => Descriptor c d IO ByteString
tokenWS = do
  hs <- get
  let pk         = curvePubToBytes . snd . fromJust . hssLocalStaticKey $ hs
      shs        = hssSymmetricHandshake hs
      (ct, shs') = encryptAndHash ((Plaintext . convert) pk) shs
  put $ hs { hssSymmetricHandshake = shs' }
  return . convert $ ct

tokenRS :: (Cipher c, Curve d)
        => ByteString
        -> Descriptor c d Identity ByteString
tokenRS buf = tokenR buf False

tokenDH :: (Cipher c, Curve d)
        => KeyPair d
        -> PublicKey d
        -> Descriptor c d Identity ()
tokenDH (sk, _) rpk = do
  hs <- get
  let shs  = hssSymmetricHandshake hs
      dh   = curveDH sk rpk
      shs' = mixKey dh shs
  put $ hs { hssSymmetricHandshake = shs' }

tokenPreS :: (Cipher c, Curve d)
          => Descriptor c d Identity ()
tokenPreS = do
  hs <- get
  let shs  = hssSymmetricHandshake hs
      pk   = fromJust . hssRemoteStaticKey $ hs
      shs' = mixHash (curvePubToBytes pk) shs
  put $ hs { hssSymmetricHandshake = shs' }

tokenPreE :: (Cipher c, Curve d)
          => Descriptor c d Identity ()
tokenPreE = do
  hs <- get
  let shs  = hssSymmetricHandshake hs
      pk   = fromJust . hssRemoteEphemeralKey $ hs
      shs' = mixHash (curvePubToBytes pk) shs
  put $ hs { hssSymmetricHandshake = shs' }

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

noiseSNR2 :: (Cipher c, Curve d)
          => Descriptor c d IO ByteString
noiseSNR2 = do
  e <- tokenWE
  hs <- get
  let kp       = fromJust $ hssLocalEphemeralKey hs
      rpk      = fromJust $ hssRemoteEphemeralKey hs
      (_, hs') = runIdentity $ runDescriptor (tokenDH kp rpk) hs
  put hs'
  return e

noiseSNI2 :: (Cipher c, Curve d)
          => ByteString
          -> Descriptor c d Identity ByteString
noiseSNI2 = undefined
