{-# LANGUAGE OverloadedStrings #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.HandshakeState
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.HandshakeState
  ( -- * Types
    HandshakeState(..),
    Descriptor,
    -- * Functions
    runDescriptor,
    handshakeState,
    writeHandshakeMsg,
    readHandshakeMsg,
    writeHandshakeMsgFinal,
    readHandshakeMsgFinal,
    encryptPayload,
    decryptPayload
  ) where

import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B (append)
import Data.Functor.Identity (Identity, runIdentity)

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.SymmetricHandshakeState
import Crypto.Noise.Types

data HandshakeState c d =
  HandshakeState { hssSymmetricHandshake :: SymmetricHandshakeState c
                 , hssLocalStaticKey     :: Maybe (KeyPair d)
                 , hssLocalEphemeralKey  :: Maybe (KeyPair d)
                 , hssRemoteStaticKey    :: Maybe (PublicKey d)
                 , hssRemoteEphemeralKey :: Maybe (PublicKey d)
                 }

type Descriptor c d m a = StateT (HandshakeState c d) m a

runDescriptor :: Monad m => Descriptor c d m a -> HandshakeState c d -> m (a, HandshakeState c d)
runDescriptor = runStateT

handshakeState :: (Cipher c, Curve d)
               => ScrubbedBytes
               -> Maybe (KeyPair d)
               -> Maybe (KeyPair d)
               -> Maybe (PublicKey d)
               -> Maybe (PublicKey d)
               -> Maybe (Descriptor c d Identity ())
               -> HandshakeState c d
handshakeState hn ls le rs re = maybe hs hs'
  where
    hs = HandshakeState (symmetricHandshake hn) ls le rs re
    hs' desc = snd $ runIdentity $ runDescriptor desc hs

writeHandshakeMsg :: (Cipher c, Curve d)
                      => HandshakeState c d
                      -> Descriptor c d IO ByteString
                      -> Plaintext
                      -> IO (ByteString, HandshakeState c d)
writeHandshakeMsg hs desc payload = do
  (d, hs') <- runDescriptor desc hs
  let shs        = hssSymmetricHandshake hs
      (ep, shs') = encryptAndHash payload shs
      hs''       = hs' { hssSymmetricHandshake = shs' }
  return (d `B.append` convert ep, hs'')

readHandshakeMsg :: (Cipher c, Curve d)
                     => HandshakeState c d
                     -> ByteString
                     -> (ByteString -> Descriptor c d Identity ByteString)
                     -> (Plaintext, HandshakeState c d)
readHandshakeMsg hs buf desc = (dp, hs'')
  where
    (d, hs')   = runIdentity $ runDescriptor (desc buf) hs
    shs        = hssSymmetricHandshake hs
    (dp, shs') = decryptAndHash (cipherBytesToText (convert d)) shs
    hs''       = hs' { hssSymmetricHandshake = shs' }

writeHandshakeMsgFinal :: (Cipher c, Curve d)
                       => HandshakeState c d
                       -> Descriptor c d IO ByteString
                       -> Plaintext
                       -> IO (ByteString, CipherState c, CipherState c)
writeHandshakeMsgFinal hs desc payload = do
  (d, hs') <- writeHandshakeMsg hs desc payload
  let shs        = hssSymmetricHandshake hs'
      (cs1, cs2) = split shs
  return (d, cs1, cs2)

readHandshakeMsgFinal :: (Cipher c, Curve d)
                      => HandshakeState c d
                      -> ByteString
                      -> (ByteString -> Descriptor c d Identity ByteString)
                      -> (Plaintext, CipherState c, CipherState c)
readHandshakeMsgFinal hs buf desc = (pt, cs1, cs2)
  where
    (pt, hs')  = readHandshakeMsg hs buf desc
    shs        = hssSymmetricHandshake hs'
    (cs1, cs2) = split shs

encryptPayload :: Cipher c
             => CipherState c
             -> Plaintext
             -> (ByteString, CipherState c)
encryptPayload cs pt = ((convert . cipherTextToBytes) ct, cs')
  where
    (ct, cs') = encryptAndIncrement ad pt cs
    ad = AssocData $ convert ("" :: ByteString)

decryptPayload :: Cipher c
            => CipherState c
            -> ByteString
            -> (Plaintext, CipherState c)
decryptPayload cs ct = (pt, cs')
  where
    (pt, cs') = decryptAndIncrement ad ((cipherBytesToText . convert) ct) cs
    ad = AssocData $ convert ("" :: ByteString)
