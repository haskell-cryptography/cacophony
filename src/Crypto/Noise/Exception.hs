-------------------------------------------------
-- |
-- Module      : Crypto.Noise.Exception
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Exception where

import Control.Exception.Safe

-- | Represents the type of key that may be associated with an exception.
data ExceptionKeyType
  = LocalEphemeral
  | LocalStatic
  | RemoteEphemeral
  | RemoteStatic
  deriving Show

-- | Represents the various exceptions which can be thrown.
--
--   * 'StaticKeyOverwrite' occurs when a static key is transmitted by the
--   remote party, but a remote static key has already been set in
--   'HandshakeOpts'.
--
--   * 'InvalidKey' occurs when a key transmitted by the remote party is
--   successfully decrypted but otherwise invalid.
--
--   * 'KeyMissing' occurs when a required key has not been provided to
--   'HandshakeOpts'. The keys which are required depend on the handshake
--   pattern chosen.
--
--   * 'InvalidPattern' occurs when a handshake pattern uses an improper token.
--   This can occur if a user-defined 'HandshakePattern' uses any token other
--   than @e@ or @s@ in a pre-message pattern.
--
--   * 'DecryptionError' occurs when any data fails to decrypt for any reason.
--   This usually occurs if the authentication tag is invalid.
--
--   * 'MessageLimitReached' occurs if the user attempts to send or receive
--   more than @2^64 - 1@ messages. This is needed because nonces are 8-bytes
--   (64 bits), and doing so would cause catastrophic key re-use.
data NoiseException = StaticKeyOverwrite
                    | InvalidKey ExceptionKeyType
                    | KeyMissing ExceptionKeyType
                    | InvalidPattern
                    | DecryptionError
                    | MessageLimitReached
                    deriving Show

instance Exception NoiseException
