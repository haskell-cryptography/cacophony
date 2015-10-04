{-# LANGUAGE TypeFamilies #-}

----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Cipher
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Cipher
  ( -- * Type families
    Ciphertext,
    SymmetricKey,
    Nonce,
    Digest,
    -- * Types
    Plaintext(..),
    AssocData(..),
    Cipher(..)
  ) where

import Data.ByteString (ByteString)

data family Ciphertext   c :: *
data family SymmetricKey c :: *
data family Nonce        c :: *
data family Digest       c :: *

newtype Plaintext c = Plaintext ByteString
newtype AssocData c = AssocData ByteString

data Cipher c =
  Cipher {
    cipherName :: ByteString,
    cipherEncrypt :: SymmetricKey c -> Nonce c -> AssocData c -> Plaintext  c -> Ciphertext c,
    cipherDecrypt :: SymmetricKey c -> Nonce c -> AssocData c -> Ciphertext c -> Plaintext  c,
    cipherGetKey  :: SymmetricKey c -> Nonce c,
    cipherHash    :: ByteString -> ByteString
}
