{-# LANGUAGE TypeFamilies #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Hash
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Hash
  ( -- * Classes
    Hash(..)
  ) where

import Crypto.Noise.Types

class Hash h where
  data ChainingKey h :: *
  data Digest      h :: *

  hashName      :: proxy h -> ScrubbedBytes
  hashLength    :: proxy h -> Int
  hash          :: ScrubbedBytes -> Digest h
  hashHKDF      :: ChainingKey h -> ScrubbedBytes -> (ChainingKey h, ScrubbedBytes)
  hashBytesToCK :: ScrubbedBytes -> ChainingKey h
  hashCKToBytes :: ChainingKey h -> ScrubbedBytes
  hashToBytes   :: Digest h -> ScrubbedBytes
