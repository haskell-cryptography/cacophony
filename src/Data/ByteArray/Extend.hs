----------------------------------------------------------------
-- |
-- Module      : Data.ByteArray.Extend
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
--
-- This module contains helper functions which can be useful at times.

module Data.ByteArray.Extend
  ( -- * Types
    ScrubbedBytes,
    -- * Functions
    convert,
    append,
    concatSB,
    bsToSB,
    bsToSB',
    sbToBS,
    sbToBS',
    sbEq
 ) where

import Data.ByteArray (ScrubbedBytes, concat, convert, append, eq)
import qualified Data.ByteString as BS (ByteString)
import qualified Data.ByteString.Lazy as BL (ByteString, toStrict, fromStrict)
import Prelude hiding (concat)

-- | Concatenates a list of 'ScrubbedBytes'.
concatSB :: [ScrubbedBytes] -> ScrubbedBytes
concatSB = concat

-- | Converts a lazy ByteString to ScrubbedBytes.
bsToSB :: BL.ByteString -> ScrubbedBytes
bsToSB = convert . BL.toStrict

-- | Strict version of 'bsToSB'.
bsToSB' :: BS.ByteString -> ScrubbedBytes
bsToSB' = convert

-- | Converts ScrubbedBytes to a lazy ByteString.
sbToBS :: ScrubbedBytes -> BL.ByteString
sbToBS = BL.fromStrict . convert

-- | Strict version of 'sbToBS''.
sbToBS' :: ScrubbedBytes -> BS.ByteString
sbToBS' = convert

-- | Equality operator for 'ScrubbedBytes'.
sbEq :: ScrubbedBytes -> ScrubbedBytes -> Bool
sbEq = eq
