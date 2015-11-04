----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Types
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Types
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

concatSB :: [ScrubbedBytes] -> ScrubbedBytes
concatSB = concat

bsToSB :: BL.ByteString -> ScrubbedBytes
bsToSB = convert . BL.toStrict

bsToSB' :: BS.ByteString -> ScrubbedBytes
bsToSB' = convert

sbToBS :: ScrubbedBytes -> BL.ByteString
sbToBS = BL.fromStrict . convert

sbToBS' :: ScrubbedBytes -> BS.ByteString
sbToBS' = convert

sbEq :: ScrubbedBytes -> ScrubbedBytes -> Bool
sbEq = eq
