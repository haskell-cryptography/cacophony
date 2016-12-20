{-# LANGUAGE TypeFamilies #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Cipher
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Cipher
  ( -- * Classes
    Cipher(..)
    -- * Types
  , AssocData
  , Plaintext
  ) where

import Data.ByteArray (ScrubbedBytes)

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

  -- | Decrypts data, returning @Nothing@ on error (such as when the auth tag
  --   is invalid).
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
type AssocData = ScrubbedBytes

-- | Represents plaintext data that can be encrypted.
type Plaintext = ScrubbedBytes

instance Show (SymmetricKey a) where
  show _ = "<symmetric key>"

instance Show (Nonce a) where
  show _ = "<nonce>"
