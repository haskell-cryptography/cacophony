{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleInstances #-}

----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Cipher.ChaChaPoly1305
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Cipher.ChaChaPoly1305
  ( -- * Types
    ChaChaPoly1305
  ) where

import Crypto.Error (throwCryptoError)
import qualified Crypto.MAC.Poly1305 as P
import qualified Crypto.Cipher.ChaChaPoly1305 as CCP
import qualified Crypto.Hash as H
import Data.Byteable
import Data.ByteArray (ScrubbedBytes)
import qualified Data.ByteArray as B (convert, append)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS (replicate)

import Crypto.Noise.Cipher

data ChaChaPoly1305

instance Cipher ChaChaPoly1305 where
  data Ciphertext   ChaChaPoly1305 = CTCCP1305 (ScrubbedBytes, P.Auth)
  data SymmetricKey ChaChaPoly1305 = SKCCP1305 ScrubbedBytes
  data Nonce        ChaChaPoly1305 = NCCP1305  CCP.Nonce
  data Digest       ChaChaPoly1305 = DCCP1305  (H.Digest H.SHA256)

  cipherName _    = "ChaChaPoly"
  cipherEncrypt   = _encrypt
  cipherDecrypt   = _decrypt
  cipherZeroNonce = _zeroNonce
  cipherIncNonce  = _incNonce
  cipherGetKey    = _getKey
  cipherHash      = _hash
  cipherHashToKey = _hashToKey
  cipherHMAC      = _hmac

instance Byteable (Ciphertext ChaChaPoly1305) where
  toBytes (CTCCP1305 (d, ad)) = B.convert d `B.append` B.convert ad

_encrypt :: SymmetricKey ChaChaPoly1305 -> Nonce ChaChaPoly1305 -> AssocData -> Plaintext -> Ciphertext ChaChaPoly1305
_encrypt (SKCCP1305 k) (NCCP1305 n) (AssocData ad) (Plaintext plaintext) = CTCCP1305 (out, authTag)
  where
    initState       = throwCryptoError $ CCP.initialize k n
    afterAAD        = CCP.finalizeAAD (CCP.appendAAD ad initState)
    (out, afterEnc) = CCP.encrypt plaintext afterAAD
    authTag         = CCP.finalize afterEnc

_decrypt :: SymmetricKey ChaChaPoly1305 -> Nonce ChaChaPoly1305 -> AssocData -> Ciphertext ChaChaPoly1305 -> Maybe Plaintext
_decrypt (SKCCP1305 k) (NCCP1305 n) (AssocData ad) (CTCCP1305 (ciphertext, provAuthTag)) =
  if provAuthTag == calcAuthTag then
    return $ Plaintext out
  else
    Nothing
  where
    initState       = throwCryptoError $ CCP.initialize k n
    afterAAD        = CCP.finalizeAAD (CCP.appendAAD ad initState)
    (out, afterDec) = CCP.decrypt ciphertext afterAAD
    calcAuthTag     = CCP.finalize afterDec

_zeroNonce :: Nonce ChaChaPoly1305
_zeroNonce = NCCP1305 $ throwCryptoError $ CCP.nonce8 constant iv
  where
    constant = BS.replicate 4 0
    iv       = BS.replicate 8 0

_incNonce :: Nonce ChaChaPoly1305 -> Nonce ChaChaPoly1305
_incNonce (NCCP1305 n) = NCCP1305 $ CCP.incrementNonce n

_getKey :: SymmetricKey ChaChaPoly1305 -> Nonce ChaChaPoly1305 -> SymmetricKey ChaChaPoly1305
_getKey k n = SKCCP1305 ct
  where
    (CTCCP1305 (ct, _)) = _encrypt k n (AssocData empty) (Plaintext zeroes)
    zeroes = B.convert . BS.replicate 32 $ 0
    empty = B.convert ("" :: ByteString)

_hash :: ByteString -> Digest ChaChaPoly1305
_hash bs = DCCP1305 $ H.hash bs

_hashToKey :: Digest ChaChaPoly1305 -> SymmetricKey ChaChaPoly1305
_hashToKey = undefined

_hmac :: SymmetricKey ChaChaPoly1305 -> Plaintext -> Digest ChaChaPoly1305
_hmac = undefined
