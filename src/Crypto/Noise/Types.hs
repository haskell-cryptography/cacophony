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
    bsToSB,
    bsToSB',
    sbToBS,
    sbToBS'
  ) where

import Data.ByteArray (ScrubbedBytes, convert, append)
import qualified Data.ByteString as BS (ByteString)
import qualified Data.ByteString.Lazy as BL (ByteString, toStrict, fromStrict)

bsToSB :: BL.ByteString -> ScrubbedBytes
bsToSB = convert . BL.toStrict

bsToSB' :: BS.ByteString -> ScrubbedBytes
bsToSB' = convert

sbToBS :: ScrubbedBytes -> BL.ByteString
sbToBS = BL.fromStrict . convert

sbToBS' :: ScrubbedBytes -> BS.ByteString
sbToBS' = convert
