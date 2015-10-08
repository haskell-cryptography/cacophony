----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Handshake
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Handshake
  ( -- * Types
    Handshake,
    -- * Functions
    noiseNN
  ) where

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Internal.HandshakeState

data Handshake c d =
  Handshake { hsPattern :: [Descriptor c]
            , hsState   :: HandshakeState c d
            }

noiseNN :: (Cipher c, Curve d) => Handshake c d
noiseNN = undefined
