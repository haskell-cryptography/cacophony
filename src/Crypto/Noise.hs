-------------------------------------------------
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
  , rekeySending
  , rekeyReceiving
    -- * Lenses
  , hoRole
  , hoPrologue
  , hoLocalStatic
  , hoLocalEphemeral
  , hoRemoteStatic
  , hoRemoteEphemeral
  ) where

import Control.Arrow   (arr, first, second, (***))
import Control.Exception.Safe
import Control.Lens
import Data.ByteArray  (ScrubbedBytes, convert)
import Data.ByteString (ByteString)
import Data.Maybe      (isJust)

import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.Handshake.State
import Crypto.Noise.Internal.NoiseState
import Crypto.Noise.Internal.SymmetricState
import Crypto.Noise.Internal.Types

-- | Creates a Noise message with the provided payload. Note that the
--   payload may not be authenticated or encrypted at all points during the
--   handshake. Please see section 7.4 of the protocol document for details.
--
--   To prevent catastrophic key re-use, this function may only be used to
--   secure 2^64 - 1 post-handshake messages.
writeMessage :: (MonadThrow m, Cipher c, DH d, Hash h)
             => ScrubbedBytes
             -> NoiseState c d h
             -> m (ByteString, NoiseState c d h)
writeMessage msg ns = maybe
  (first convertArr <$> resumeHandshake msg ns)
  (\cs -> (ctToBytes *** updateState) <$> encryptWithAd mempty msg cs)
  (ns ^. nsSendingCipherState)
  where
    convertArr  = arr convert
    ctToBytes   = convertArr . arr cipherTextToBytes
    updateState = arr $ \cs -> ns & nsSendingCipherState .~ Just cs

-- | Reads a Noise message and returns the embedded payload. If the
--   handshake fails, a 'HandshakeError' will be returned. After the handshake
--   is complete, if decryption fails a 'DecryptionError' is returned.
--
--   To prevent catastrophic key re-use, this function may only be used to
--   receive 2^64 - 1 post-handshake messages.
readMessage :: (MonadThrow m, Cipher c, DH d, Hash h)
            => ByteString
            -> NoiseState c d h
            -> m (ScrubbedBytes, NoiseState c d h)
readMessage ct ns = maybe
  (resumeHandshake (convert ct) ns)
  (\cs -> second updateState <$> decryptWithAd mempty ct' cs)
  (ns ^. nsReceivingCipherState)
  where
    ct'         = cipherBytesToText . convert $ ct
    updateState = arr $ \cs -> ns & nsReceivingCipherState .~ Just cs

-- | For handshake patterns where the remote party's static key is
--   transmitted, this function can be used to retrieve it. This allows
--   for the creation of public key-based access-control lists.
remoteStaticKey :: NoiseState c d h
                -> Maybe (PublicKey d)
remoteStaticKey ns = ns ^. nsHandshakeState . hsOpts . hoRemoteStatic

-- | Returns @True@ if the handshake is complete.
handshakeComplete :: NoiseState c d h
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
--   See section 11.2 of the protocol for details.
handshakeHash :: Hash h
              => NoiseState c d h
              -> ScrubbedBytes
handshakeHash ns = either id hashToBytes
                   $ ns ^. nsHandshakeState . hsSymmetricState . ssh

-- | Rekeys the sending 'CipherState'.
rekeySending :: (Cipher c, DH d, Hash h)
             => NoiseState c d h
             -> NoiseState c d h
rekeySending ns = ns & nsSendingCipherState %~ (<*>) (pure rekey)

-- | Rekeys the receiving 'CipherState'.
rekeyReceiving :: (Cipher c, DH d, Hash h)
               => NoiseState c d h
               -> NoiseState c d h
rekeyReceiving ns = ns & nsReceivingCipherState %~ (<*>) (pure rekey)
