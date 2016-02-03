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
    SendingCipherState,
    ReceivingCipherState,
    HandshakeCallbacks(..),
    HandshakeState,
    HandshakeStateParams(..),
    -- * Functions
    handshakeState,
    runHandshake,
    encryptPayload,
    decryptPayload
  ) where

import Crypto.Noise.Internal.HandshakeState
