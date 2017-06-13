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
    HandshakePattern
  , HandshakeRole(..)
  , HandshakeOpts
  , NoiseException(..)
  , NoiseState
  , NoiseResult(..)
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
  , handshakePattern
    -- * HandshakeOpts Setters
  , setRole
  , setPrologue
  , setLocalEphemeral
  , setLocalStatic
  , setRemoteEphemeral
  , setRemoteStatic
  ) where

import Control.Arrow   (arr, second, (***))
import Control.Exception.Safe
import Control.Lens
import Data.ByteArray  (ScrubbedBytes)
import Data.Maybe      (isJust)

import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Exception
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.Handshake.Pattern
import Crypto.Noise.Internal.Handshake.State
import Crypto.Noise.Internal.NoiseState
import Crypto.Noise.Internal.SymmetricState

data NoiseResult c d h
  = NoiseResultMessage   ScrubbedBytes (NoiseState c d h)
  | NoiseResultNeedPSK   (NoiseState c d h)
  | NoiseResultException SomeException

-- | Creates a Noise message with the provided payload. Note that the
--   payload may not be authenticated or encrypted at all points during the
--   handshake. Please see section 7.4 of the protocol document for details.
--
--   To prevent catastrophic key re-use, this function may only be used to
--   secure 2^64 - 1 post-handshake messages.
writeMessage :: (Cipher c, DH d, Hash h)
             => ScrubbedBytes
             -> NoiseState c d h
             -> NoiseResult c d h
writeMessage msg ns = maybe
  (convertHandshakeResult $ resumeHandshake msg ns)
  (convertTransportResult . encryptMsg)
  (ns ^. nsSendingCipherState)
  where
    ctToMsg       = arr cipherTextToBytes
    updateState   = arr $ \cs -> ns & nsSendingCipherState .~ Just cs
    encryptMsg cs = (ctToMsg *** updateState) <$> encryptWithAd mempty msg cs

-- | Reads a Noise message and returns the embedded payload. If the
--   handshake fails, a 'HandshakeError' will be returned. After the handshake
--   is complete, if decryption fails a 'DecryptionError' is returned.
--
--   To prevent catastrophic key re-use, this function may only be used to
--   receive 2^64 - 1 post-handshake messages.
readMessage :: (Cipher c, DH d, Hash h)
            => ScrubbedBytes
            -> NoiseState c d h
            -> NoiseResult c d h
readMessage ct ns = maybe
  (convertHandshakeResult $ resumeHandshake ct ns)
  (convertTransportResult . decryptMsg)
  (ns ^. nsReceivingCipherState)
  where
    ct'           = cipherBytesToText ct
    updateState   = arr $ \cs -> ns & nsReceivingCipherState .~ Just cs
    decryptMsg cs = second updateState <$> decryptWithAd mempty ct' cs

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

--------------------------------------------------------------------------------

convertHandshakeResult :: (Cipher c, DH d, Hash h)
                       => Either SomeException (HandshakeResult, NoiseState c d h)
                       -> NoiseResult c d h
convertHandshakeResult hsr = case hsr of
  Left ex -> NoiseResultException ex
  Right (HandshakeResultMessage m, ns) -> NoiseResultMessage m ns
  Right (HandshakeResultNeedPSK  , ns) -> NoiseResultNeedPSK ns

convertTransportResult :: (Cipher c, DH d, Hash h)
                       => Either SomeException (ScrubbedBytes, NoiseState c d h)
                       -> NoiseResult c d h
convertTransportResult = either NoiseResultException (uncurry NoiseResultMessage)
