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
    append
  ) where

import Data.ByteArray (ScrubbedBytes, convert, append)
