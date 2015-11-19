----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Types
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Types
  ( -- * Types
    ScrubbedBytes,
    NoiseException(..),
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

import Control.Exception (Exception)
import Data.ByteArray (ScrubbedBytes, concat, convert, append, eq)
import qualified Data.ByteString as BS (ByteString)
import qualified Data.ByteString.Lazy as BL (ByteString, toStrict, fromStrict)
import Prelude hiding (concat)

-- | Represents exceptions which can occur. 'DecryptionFailure' is thrown
--   if a symmetric decryption operation fails, which is usually the result
--   of an invalid authentication tag. 'HandshakeStateFailure' is thrown if
--   the 'Crypto.Noise.Handshake.HandshakeState' is improperly initialized
--   for the given handshake type.
--
--   If your goal is to detect an invalid PSK, prologue, etc, you'll want
--   to catch 'DecryptionFailure'.
data NoiseException = DecryptionFailure String
                    | HandshakeStateFailure String
  deriving (Show)

instance Exception NoiseException

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
