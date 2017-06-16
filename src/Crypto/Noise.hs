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
    NoiseState
  , NoiseResult(..)
  , NoiseException(..)
  , HandshakePattern
  , HandshakeRole(..)
  , HandshakeOpts
    -- * Functions
  , defaultHandshakeOpts
  , noiseState
  , writeMessage
  , readMessage
  , processPSKs
  , remoteStaticKey
  , handshakeComplete
  , handshakeHash
  , rekeySending
  , rekeyReceiving
  , handshakePattern
    -- * HandshakeOpts Setters
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
import Crypto.Noise.Internal.Handshake.Pattern hiding (psk)
import Crypto.Noise.Internal.Handshake.State
import Crypto.Noise.Internal.NoiseState
import Crypto.Noise.Internal.SymmetricState

-- | This type is used to indicate to the user the result of either writing or
--   reading a message. In the simplest case, when processing a handshake or
--   transport message, the (en|de)crypted message and mutated state will be
--   available in 'NoiseResultMessage'.
--
--   If during the course of the handshake a pre-shared key is needed, a
--   'NoiseResultNeedPSK' value will be returned along with the mutated state.
--   To continue, the user must re-issue the 'writeMessage' or 'readMessage'
--   call, passing in the PSK as the payload. If no further PSKs are required,
--   the result will be 'NoiseResultMessage'.
--
--   If an exception is encountered at any point while processing a handshake or
--   transport message, 'NoiseResultException' will be returned.
data NoiseResult c d h
  = NoiseResultMessage   ScrubbedBytes (NoiseState c d h)
  | NoiseResultNeedPSK   (NoiseState c d h)
  | NoiseResultException SomeException

-- | Creates a handshake or transport message with the provided payload. Note
--   that the payload may not be authenticated or encrypted at all points during
--   the handshake. Please see section 7.4 of the protocol document for details.
--
--   If a previous call to this function indicated that a pre-shared key is
--   needed, it shall be provided as the payload. See the documentation of
--   'NoiseResult' for details.
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

-- | Reads a handshake or transport message and returns the embedded payload. If
--   the handshake fails, a 'HandshakeError' will be returned. After the
--   handshake is complete, if decryption fails a 'DecryptionError' is returned.
--
--   If a previous call to this function indicated that a pre-shared key is
--   needed, it shall be provided as the payload. See the documentation of
--   'NoiseResult' for details.
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

-- | Given an operation ('writeMessage' or 'readMessage'), a list of PSKs, and
--   a 'NoiseResult', this function will repeatedly apply PSKs to the NoiseState
--   until no more are requested or the list of PSKs becomes empty. This is
--   useful for patterns which require one or more PSKs.
processPSKs :: (Cipher c, DH d, Hash h)
            => (ScrubbedBytes -> NoiseState c d h -> NoiseResult c d h)
            -> [ScrubbedBytes]
            -> NoiseResult c d h
            -> ([ScrubbedBytes], NoiseResult c d h)
processPSKs _ []                result = ([], result)
processPSKs f psks@(psk : rest) result = case result of
  NoiseResultNeedPSK state' -> processPSKs f rest (f psk state')
  r -> (psks, r)

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

-- | Rekeys the sending @CipherState@ according to section 11.3 of the protocol.
rekeySending :: (Cipher c, DH d, Hash h)
             => NoiseState c d h
             -> NoiseState c d h
rekeySending ns = ns & nsSendingCipherState %~ (<*>) (pure rekey)

-- | Rekeys the receiving @CipherState@ according to section 11.3 of the
--   protocol.
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
