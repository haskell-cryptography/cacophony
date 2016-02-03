{-# LANGUAGE TypeFamilies #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Cipher
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Cipher
  ( -- * Classes
    Cipher(..),
    -- * Types
    AssocData(..)
  ) where

import Crypto.Noise.Types

-- | Typeclass for ciphers.
class Cipher c where
  -- | Represents encrypted data containing an authentication tag.
  data Ciphertext   c :: *

  -- | Represents a symmetric key.
  data SymmetricKey c :: *

  -- | Represents a nonce.
  data Nonce        c :: *

  -- | Returns the name of the cipher. This is used when generating
  --   the handshake name.
  cipherName        :: proxy c -> ScrubbedBytes

  -- | Encrypts data.
  cipherEncrypt     :: SymmetricKey c
                    -> Nonce c
                    -> AssocData
                    -> Plaintext
                    -> Ciphertext c

  -- | Decrypts data. Will fail catastrophically if the authentication
  --   tag is invalid.
  cipherDecrypt     :: SymmetricKey c
                    -> Nonce c
                    -> AssocData
                    -> Ciphertext c
                    -> Maybe Plaintext

  -- | Returns a Nonce set to zero.
  cipherZeroNonce   :: Nonce c

  -- | Increments a nonce.
  cipherIncNonce    :: Nonce c -> Nonce c

  -- | Imports a symmetric key. If the input is greater than 32 bytes, it
  --   is truncated.
  cipherBytesToSym  :: ScrubbedBytes -> SymmetricKey c

  -- | Exports a Ciphertext. The authentication tag follows the
  --   actual ciphertext.
  cipherTextToBytes :: Ciphertext c -> ScrubbedBytes

  -- | Imports a Ciphertext.
  cipherBytesToText :: ScrubbedBytes -> Ciphertext c

-- | Represents the associated data for AEAD.
newtype AssocData = AssocData ScrubbedBytes
