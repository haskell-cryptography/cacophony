{-# LANGUAGE TypeFamilies #-}

----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Cipher
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Cipher
  ( -- * Classes
    Cipher(..),
    -- * Types
    Plaintext(..),
    AssocData(..)
  ) where

import Data.Byteable
import Data.ByteArray (ScrubbedBytes, convert)
import Data.ByteString (ByteString)

class Cipher c where
  data Ciphertext   c :: *
  data SymmetricKey c :: *
  data Nonce        c :: *
  data Digest       c :: *

  cipherName      :: c -> ByteString
  cipherEncrypt   :: SymmetricKey c -> Nonce c -> AssocData -> Plaintext -> Ciphertext c
  cipherDecrypt   :: SymmetricKey c -> Nonce c -> AssocData -> Ciphertext c -> Maybe Plaintext
  cipherZeroNonce :: Nonce c
  cipherIncNonce  :: Nonce c -> Nonce c
  cipherGetKey    :: SymmetricKey c -> Nonce c -> SymmetricKey c
  cipherHash      :: ByteString -> Digest c
  cipherHashToKey :: Digest c -> SymmetricKey c
  cipherHMAC      :: SymmetricKey c -> Plaintext -> Digest c

newtype Plaintext = Plaintext ScrubbedBytes
newtype AssocData = AssocData ScrubbedBytes

instance Byteable Plaintext where
  toBytes (Plaintext pt) = convert pt
