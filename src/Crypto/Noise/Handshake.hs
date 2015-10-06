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

import Crypto.Noise.Curve
import Crypto.Noise.Internal.HandshakeState

data Token c = TokenE (PublicKey c)
             | TokenS (PublicKey c)
             | TokenDHEE
             | TokenDHES
             | TokenDHSE
             | TokenDHSS

type Descriptor c = [Token c]

data Handshake c d =
  Handshake { hsPattern :: [Descriptor c]
            , hsState   :: HandshakeState c d
            }

noiseNN :: Handshake c d
noiseNN = undefined
