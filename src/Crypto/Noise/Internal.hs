----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal
  ( -- * Types
    CipherState,
    -- * API
    newCipherState,
    encryptAndIncrement,
    decryptAndIncrement
  ) where

import Data.ByteString (ByteString)
import Data.LargeWord  (Word256)
import Data.Word       (Word64)

newtype PlainText = PlainText ByteString
newtype CipherText = CipherText ByteString
newtype SymmetricKey = SymmetricKey Word256
newtype Nonce = Nonce Word64

data CipherState =
  CipherState { k :: SymmetricKey
              , n :: Nonce
              }

newCipherState :: CipherState
newCipherState = undefined

encryptAndIncrement :: CipherState -> PlainText -> (CipherText, CipherState)
encryptAndIncrement cs pt = undefined

decryptAndIncrement :: CipherState -> CipherText -> (PlainText, CipherState)
decryptAndIncrement cs ct = undefined
