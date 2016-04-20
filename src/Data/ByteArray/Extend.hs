{-# LANGUAGE GeneralizedNewtypeDeriving #-}
----------------------------------------------------------------
-- |
-- Module      : Data.ByteArray.Extend
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
--
-- This module provides a wrapper for the @memory@ package's
-- ScrubbedBytes data type.

module Data.ByteArray.Extend
  ( -- * Types
    ScrubbedBytes
    -- * Functions
  , convert
  , length
  , replicate
  , concat
  , splitAt
  ) where

import Control.DeepSeq       (NFData)
import Data.ByteArray        (ByteArray, ByteArrayAccess, convert,
                              length, replicate, concat, splitAt)
import qualified Data.ByteArray as BA (ScrubbedBytes)
import Data.ByteString.Char8 (pack)
import Data.String           (IsString(..))
import Prelude hiding        (length, replicate, concat, splitAt)

-- | Represents plaintext data which will be erased when it falls
--   out of scope.
newtype ScrubbedBytes = ScrubbedBytes BA.ScrubbedBytes
                        deriving (Eq, Show, NFData, Monoid, Ord, ByteArrayAccess, ByteArray)

instance IsString ScrubbedBytes where
  fromString = ScrubbedBytes . convert . pack
