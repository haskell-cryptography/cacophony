{-# LANGUAGE TypeFamilies #-}
-------------------------------------------------
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

import Data.ByteArray (ScrubbedBytes, replicate)
import Prelude hiding (replicate)

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

  -- | Returns a new 32-byte cipher key as a pseudorandom function of @k@.
  --   Defaults to:
  --
  --   @cipherEncrypt k maxNonce "" zeros@
  --
  --   where @maxNonce = 2^64 - 1@ and @zeros@ is a sequence of 32 bytes filed
  --   with zeros.
  cipherRekey       :: SymmetricKey c
                    -> SymmetricKey c
  cipherRekey k = cipherBytesToSym  .
                  cipherTextToBytes $
                  cipherEncrypt k maxNonce "" zeros
    where
      maxNonce = cipherNonce $ 2 ^ (64 :: Integer) - 1
      zeros    = replicate 32 0

  -- | Converts an integer to a Nonce.
  cipherNonce       :: Integer -> Nonce c

  -- | Increments a nonce.
  cipherIncNonce    :: Nonce c -> Nonce c

  -- | Imports a symmetric key. If the input is greater than 32 bytes, it
  --   is truncated.
  cipherBytesToSym  :: ScrubbedBytes -> SymmetricKey c

  -- | Exports a symmetric key. Use with care.
  cipherSymToBytes  :: SymmetricKey c -> ScrubbedBytes

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
