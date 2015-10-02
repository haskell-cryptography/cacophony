----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal
  ( -- * Types
    PlainText,
    CipherText,
    SymmetricKey,
    Nonce,
    HashOutput,
    HandshakeName,
    CipherState,
    SymmetricHandshakeState,
    -- * API
    cipherState,
    encryptAndIncrement,
    decryptAndIncrement,
    symmetricHandshake
  ) where

import Data.ByteString (ByteString)
import Data.LargeWord  (Word256)
import Data.Word       (Word64)

newtype PlainText = PlainText ByteString
newtype CipherText = CipherText ByteString
newtype SymmetricKey = SymmetricKey Word256
newtype Nonce = Nonce Word64
newtype HashOutput = HashOutput Word256
newtype HandshakeName = HandshakeName ByteString
newtype DHOutput = DHOutput ByteString

data CipherState =
  CipherState { k :: SymmetricKey
              , n :: Nonce
              }

data SymmetricHandshakeState =
  SymmetricHandshakeState { hasKey :: Bool
                          , h       :: HashOutput
                          }

cipherState :: CipherState
cipherState = undefined

encryptAndIncrement :: CipherState -> PlainText -> (CipherText, CipherState)
encryptAndIncrement cs pt = undefined

decryptAndIncrement :: CipherState -> CipherText -> (PlainText, CipherState)
decryptAndIncrement cs ct = undefined

symmetricHandshake :: HandshakeName -> SymmetricHandshakeState
symmetricHandshake = undefined

--mixKey :: DHOutput -> 
