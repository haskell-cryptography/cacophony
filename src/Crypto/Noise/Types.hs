----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Types
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
--

module Crypto.Noise.Types
  ( -- * Types
    NoiseException(..),
    Plaintext(..)
  ) where

import Control.DeepSeq       (NFData(..))
import Control.Exception     (Exception)
import Data.ByteString.Char8 (pack)
import Data.String           (IsString(..))

import Data.ByteArray.Extend

-- | Represents exceptions which can occur. 'DecryptionFailure' is thrown
--   if a symmetric decryption operation fails, which is usually the result
--   of an invalid authentication tag. 'HandshakeStateFailure' is thrown if
--   the 'Crypto.Noise.Handshake.HandshakeState' is improperly initialized
--   for the given handshake type. 'HandshakeAborted' is thrown if the
--   handshake is aborted by the 'Crypto.Noise.Handshake.hscbStaticIn'
--   function.
--
--   If your goal is to detect an invalid PSK, prologue, etc, you'll want
--   to catch 'DecryptionFailure'.
data NoiseException = DecryptionFailure String
                    | HandshakeStateFailure String
                    | HandshakeAborted String
  deriving (Show)

instance Exception NoiseException

-- | Represents plaintext which can be encrypted.
newtype Plaintext = Plaintext ScrubbedBytes

instance IsString Plaintext where
  fromString = Plaintext . convert . pack

instance Eq Plaintext where
  (Plaintext pt1) == (Plaintext pt2) = pt1 `sbEq` pt2

instance Show Plaintext where
  show (Plaintext pt) = show . sbToBS' $ pt

instance NFData Plaintext where
  rnf (Plaintext p) = rnf p
