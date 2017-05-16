{-# LANGUAGE TypeFamilies #-}
-------------------------------------------------
-- |
-- Module      : Crypto.Noise.Hash
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Hash
  ( -- * Classes
    Hash(..)
  ) where

import Data.ByteArray (ScrubbedBytes)
import Data.Word      (Word8)

-- | Typeclass for hashes.
class Hash h where
  -- | Represents a chaining key used as part of HKDF.
  data ChainingKey h :: *

  -- | Represents a hash digest.
  data Digest      h :: *

  -- | Returns the name of the hash. This is used when generating the
  --   handshake name.
  hashName      :: proxy h -> ScrubbedBytes

  -- | Returns the length of the hash output in bytes.
  hashLength    :: proxy h -> Int

  -- | Hashes data.
  hash          :: ScrubbedBytes -> Digest h

  -- | Performs HKDF.
  hashHKDF      :: ChainingKey h
                -> ScrubbedBytes
                -> Word8
                -> [ScrubbedBytes]

  -- | Converts a series of bytes to a chaining key.
  hashBytesToCK :: ScrubbedBytes -> ChainingKey h

  -- | Converts a chaining key to a series of bytes.
  hashCKToBytes :: ChainingKey h -> ScrubbedBytes

  -- | Converts a hash digest to a series of bytes.
  hashToBytes   :: Digest h -> ScrubbedBytes
