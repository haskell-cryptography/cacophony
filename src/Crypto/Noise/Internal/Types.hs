----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.Types
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.Types where

import Control.Exception.Safe

-- | Represents the various exceptions which can be thrown.
--
--   * 'InvalidHandshakeOptions' occurs when a key that is needed is missing, or
--   when a key is provided that shouldn't be. For example, it would be an
--   error for the initiator to provide a remote static key if using the
--   @Noise_NX@ pattern, because that key is transmitted during the
--   handshake.
--
--   * 'DecryptionError' occurs when a non-handshake message fails to be
--   decrypted.
--
--   * 'HandshakeError' occurs when a handshake message fails to be
--   processed. This can be due to an invalid transmitted ephemeral key,
--   a transmitted static key which fails to be decrypted, or a handshake
--   message payload which fails to be decrypted.
--
--   * 'MessageLimitReached' occurs if the user attempts to send or receive
--   more than 2^64 messages. This is needed because nonces are 8-bytes
--   (64 bits), and doing so would cause catastrophic key re-use.
data NoiseException = InvalidHandshakeOptions String
                    | DecryptionError String
                    | HandshakeError String
                    | MessageLimitReached String
                    deriving Show

instance Exception NoiseException
