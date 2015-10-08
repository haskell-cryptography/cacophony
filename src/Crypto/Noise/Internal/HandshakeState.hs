----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.HandshakeState
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.HandshakeState
  ( -- * Types
    HandshakeState,
    Token(..),
    Descriptor,
    -- * Functions
    handshakeState,
    writeHandshakeMessage,
    readHandshakeMessage
  ) where

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Internal.SymmetricHandshakeState
import Crypto.Noise.Types

data Token d = TokenE (PublicKey d)
             | TokenS (PublicKey d)
             | TokenDHEE
             | TokenDHES
             | TokenDHSE
             | TokenDHSS

type Descriptor d = [Token d]

data HandshakeState c d =
  HandshakeState { hssSymmetricHandshake :: SymmetricHandshakeState c
                 , hssLocalStaticKey     :: Maybe (KeyPair d)
                 , hssLocalEphemeralKey  :: Maybe (KeyPair d)
                 , hssRemoteStaticKey    :: Maybe (PublicKey d)
                 , hssRemoteEphemeralKey :: Maybe (PublicKey d)
                 }

handshakeState :: (Cipher c, Curve d)
               => ScrubbedBytes
               -> Maybe (KeyPair d)
               -> Maybe (KeyPair d)
               -> Maybe (PublicKey d)
               -> Maybe (PublicKey d)
               -> HandshakeState c d
handshakeState hn = HandshakeState (symmetricHandshake hn)

writeHandshakeMessage :: undefined
writeHandshakeMessage = undefined

readHandshakeMessage :: undefined
readHandshakeMessage = undefined
