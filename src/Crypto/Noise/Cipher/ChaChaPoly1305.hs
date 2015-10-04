{-# LANGUAGE OverloadedStrings, TypeFamilies #-}

----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Cipher.ChaChaPoly1305
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Cipher.ChaChaPoly1305
  ( ChaChaPoly1305,
    chaChaPoly1305,
    -- * Type families
    Ciphertext(..),
    SymmetricKey(..),
    Nonce(..),
    Digest(..)
  ) where

import Data.ByteString (ByteString)
import qualified Crypto.MAC.Poly1305 as P
import qualified Crypto.Cipher.ChaChaPoly1305 as CCP
import qualified Crypto.Hash as H

import Crypto.Noise.Cipher

data ChaChaPoly1305

data instance Ciphertext   ChaChaPoly1305 = Ciphertext   (ByteString, P.Auth)
data instance SymmetricKey ChaChaPoly1305 = SymmetricKey ByteString
data instance Nonce        ChaChaPoly1305 = Nonce        CCP.Nonce
data instance Digest       ChaChaPoly1305 = Digest       H.SHA256

chaChaPoly1305 :: Cipher ChaChaPoly1305
chaChaPoly1305 =
  Cipher { cipherName = "ChaChaPoly"
         , cipherEncrypt = _encrypt
         , cipherDecrypt = _decrypt
         , cipherGetKey  = _getKey
         , cipherHash    = _hash
         }

_encrypt :: SymmetricKey c -> Nonce c -> AssocData c -> Plaintext  c -> Ciphertext c
_encrypt = undefined

_decrypt :: SymmetricKey c -> Nonce c -> AssocData c -> Ciphertext c -> Plaintext  c
_decrypt = undefined

_getKey :: SymmetricKey c -> Nonce c
_getKey = undefined

_hash :: ByteString -> ByteString
_hash = undefined
