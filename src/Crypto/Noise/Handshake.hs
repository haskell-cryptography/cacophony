----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Handshake
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
--
-- For more information regarding HandshakePatterns, please see the
-- "Crypto.Noise.HandshakePatterns" module.
module Crypto.Noise.Handshake
  ( -- * Types
    HandshakeState,
    MessagePattern,
    MessagePatternIO,
    HandshakePattern,
    CipherState,
    -- * Functions
    getRemoteStaticKey,
    handshakeState,
    writeMessage,
    readMessage,
    writeMessageFinal,
    readMessageFinal,
    encryptPayload,
    decryptPayload
  ) where

import Crypto.Noise.Internal.HandshakeState
import Crypto.Noise.Internal.CipherState
