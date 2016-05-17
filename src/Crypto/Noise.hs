{-# LANGUAGE OverloadedStrings #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
--
-- Please see the README for usage information.

module Crypto.Noise
  ( -- * Types
    HandshakeRole(..)
  , HandshakeOpts
  , NoiseException(..)
  , NoiseState
    -- * Functions
  , defaultHandshakeOpts
  , noiseState
  , writeMessage
  , readMessage
  , remoteStaticKey
  , handshakeComplete
  , handshakeHash
  , setSecondaryKey
    -- * Lenses
  , hoPattern
  , hoRole
  , hoPrologue
  , hoPreSharedKey
  , hoLocalStatic
  , hoLocalSemiEphemeral
  , hoLocalEphemeral
  , hoRemoteStatic
  , hoRemoteSemiEphemeral
  , hoRemoteEphemeral
  ) where

import Control.Arrow
import Control.Lens
import Data.ByteString (ByteString)
import Data.Maybe      (isJust)
import Prelude hiding  (length)

import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.Handshake
import Crypto.Noise.Internal.NoiseState
import Crypto.Noise.Internal.SymmetricState
import Crypto.Noise.Internal.Types
import Data.ByteArray.Extend

-- | Creates a Noise message with the provided payload. Note that the
--   payload may not be authenticated or encrypted at all points during the
--   handshake. Please see section 8.4 of the protocol document for details.
--
--   To prevent catastrophic key re-use, this function may only be used to
--   secure 2^64 post-handshake messages.
writeMessage :: (Cipher c, DH d, Hash h)
             => NoiseState c d h
             -> ScrubbedBytes
             -> Either NoiseException (ByteString, NoiseState c d h)
writeMessage ns msg = right toByteString $
  maybe (runHandshake msg ns)
        (right (ctToBytes *** updateState) . encryptAndIncrement "" msg)
        (ns ^. nsSendingCipherState)
  where
    ctToBytes    = arr cipherTextToBytes
    updateState  = arr $ \cs -> ns & nsSendingCipherState .~ Just cs
    toByteString = first (arr convert)

-- | Reads a Noise message and returns the embedded payload. If the
--   handshake fails, a 'HandshakeError' will be returned. After the handshake
--   is complete, if decryption fails a 'DecryptionError' is returned.
--
--   To prevent catastrophic key re-use, this function may only be used to
--   receive 2^64 post-handshake messages.
readMessage :: (Cipher c, DH d, Hash h)
            => NoiseState c d h
            -> ByteString
            -> Either NoiseException (ScrubbedBytes, NoiseState c d h)
readMessage ns ct =
  maybe (runHandshake (convert ct) ns)
        ((right . second) updateState . (decryptAndIncrement "" . cipherBytesToText . convert) ct)
        (ns ^. nsReceivingCipherState)
  where
    updateState = arr $ \cs -> ns & nsReceivingCipherState .~ Just cs

-- | For handshake patterns where the remote party's static key is
--   transmitted, this function can be used to retrieve it. This allows
--   for the creation of public key-based access-control lists.
remoteStaticKey :: (Cipher c, DH d, Hash h)
                => NoiseState c d h
                -> Maybe (PublicKey d)
remoteStaticKey ns = ns ^. nsHandshakeState . hsOpts . hoRemoteStatic

-- | Returns @True@ if the handshake is complete.
handshakeComplete :: (Cipher c, DH d, Hash h)
                  => NoiseState c d h
                  -> Bool
handshakeComplete ns = isJust (ns ^. nsSendingCipherState) &&
                       isJust (ns ^. nsReceivingCipherState)

-- | Retrieves the @h@ value associated with the conversation's
--   @SymmetricState@. This value is intended to be used for channel
--   binding. For example, the initiator might cryptographically sign this
--   value as part of some higher-level authentication scheme.
--
--   The value returned by this function is only meaningful after the
--   handshake is complete.
--
--   See section 9.4 of the protocol for details.
handshakeHash :: (Cipher c, DH d, Hash h)
              => NoiseState c d h
              -> ScrubbedBytes
handshakeHash ns = either id hashToBytes
                   $ ns ^. nsHandshakeState . hsSymmetricState . ssh

-- | Sets a secondary symmetric key. This must be 32 bytes in length.
--
--   See section 9.5 of the protocol for details.
setSecondaryKey :: (Cipher c, DH d, Hash h)
                => NoiseState c d h
                -> ScrubbedBytes
                -> NoiseState c d h
setSecondaryKey ns k | length k == 32 = ns & nsHandshakeState . hsSymmetricState . ssk .~ k
                     | otherwise      = error "secondary key must be 32 bytes in length"
