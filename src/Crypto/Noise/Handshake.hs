----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Handshake
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX
--
-- For more information regarding Descriptors, please see the
-- "Crypto.Noise.Descriptors" module.
module Crypto.Noise.Handshake
  ( -- * Types
    HandshakeState,
    Descriptor,
    DescriptorIO,
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
