----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Handshake
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
--
-- For more information regarding MessagePatterns, please see the
-- "Crypto.Noise.MessagePatterns" module.
module Crypto.Noise.Handshake
  ( -- * Types
    HandshakeState,
    MessagePattern,
    MessagePatternIO,
    CipherState,
    -- * Functions
    getRemoteStaticKey,
    handshakeState,
    writeHandshakeMsg,
    readHandshakeMsg,
    writeHandshakeMsgFinal,
    readHandshakeMsgFinal,
    encryptPayload,
    decryptPayload
  ) where

import Crypto.Noise.Internal.HandshakeState
import Crypto.Noise.Internal.CipherState
