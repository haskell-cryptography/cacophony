----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Handshake
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Handshake
  ( -- * Types
    HandshakeState,
    -- * Functions
    getRemoteStaticKey,
    handshakeState,
    writeHandshakeMsg,
    readHandshakeMsg,
    writeHandshakeMsgFinal,
    readHandshakeMsgFinal,
    encryptPayload,
    decryptPayload,
    -- * Modules
    module Crypto.Noise.Internal.Descriptor
  ) where

import Crypto.Noise.Internal.HandshakeState
import Crypto.Noise.Internal.Descriptor
