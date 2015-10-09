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
import qualified Crypto.Cipher.ChaChaPoly1305 as CCP
import qualified Crypto.Hash as H
import qualified Crypto.MAC.HMAC as M
import qualified Crypto.MAC.Poly1305 as P
import qualified Data.ByteArray as B (drop, length)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS (replicate)

import Crypto.Noise.Cipher
import Crypto.Noise.Types

data ChaChaPoly1305

instance Cipher ChaChaPoly1305 where
  newtype Ciphertext   ChaChaPoly1305 = CTCCP1305 ScrubbedBytes
  newtype SymmetricKey ChaChaPoly1305 = SKCCP1305 ScrubbedBytes
  newtype Nonce        ChaChaPoly1305 = NCCP1305  CCP.Nonce
  newtype Digest       ChaChaPoly1305 = DCCP1305  (H.Digest H.SHA256)

  cipherName _      = convert ("ChaChaPoly" :: ByteString)
  cipherEncrypt     = encrypt
  cipherDecrypt     = decrypt
  cipherZeroNonce   = zeroNonce
  cipherIncNonce    = incNonce
  cipherGetKey      = getKey
  cipherHash        = hash
  cipherHMAC        = hmac
  cipherHashToKey   = hashToKey
  cipherHashToBytes = hashToBytes
  cipherTextToBytes = ctToBytes
  cipherBytesToText = bytesToCt

encrypt :: SymmetricKey ChaChaPoly1305 -> Nonce ChaChaPoly1305 -> AssocData -> Plaintext -> Ciphertext ChaChaPoly1305
encrypt (SKCCP1305 k) (NCCP1305 n) (AssocData ad) (Plaintext plaintext) =
  CTCCP1305 $ out `append` convert authTag
  where
    initState       = throwCryptoError $ CCP.initialize k n
    afterAAD        = CCP.finalizeAAD (CCP.appendAAD ad initState)
    (out, afterEnc) = CCP.encrypt plaintext afterAAD
    authTag         = CCP.finalize afterEnc

decrypt :: SymmetricKey ChaChaPoly1305 -> Nonce ChaChaPoly1305 -> AssocData -> Ciphertext ChaChaPoly1305 -> Maybe Plaintext
decrypt (SKCCP1305 k) (NCCP1305 n) (AssocData ad) (CTCCP1305 ct) =
  if provAuthTag == calcAuthTag then
    return $ Plaintext out
  else
    Nothing
  where
    provAuthTag     = P.Auth $ convert $ B.drop (B.length ct - 16) ct
    initState       = throwCryptoError $ CCP.initialize k n
    afterAAD        = CCP.finalizeAAD (CCP.appendAAD ad initState)
    (out, afterDec) = CCP.decrypt ct afterAAD
    calcAuthTag     = CCP.finalize afterDec

zeroNonce :: Nonce ChaChaPoly1305
zeroNonce = NCCP1305 $ throwCryptoError $ CCP.nonce8 constant iv
  where
    constant = BS.replicate 4 0
    iv       = BS.replicate 8 0

incNonce :: Nonce ChaChaPoly1305 -> Nonce ChaChaPoly1305
incNonce (NCCP1305 n) = NCCP1305 $ CCP.incrementNonce n

getKey :: SymmetricKey ChaChaPoly1305 -> Nonce ChaChaPoly1305 -> SymmetricKey ChaChaPoly1305
getKey k n = SKCCP1305 ct
  where
    (CTCCP1305 ct) = encrypt k n (AssocData empty) (Plaintext zeroes)
    zeroes = convert . BS.replicate 32 $ 0
    empty = convert ("" :: ByteString)

hash :: ScrubbedBytes -> Digest ChaChaPoly1305
hash bs = DCCP1305 $ H.hash bs

hmac :: SymmetricKey ChaChaPoly1305 -> ScrubbedBytes -> Digest ChaChaPoly1305
hmac (SKCCP1305 k) d = DCCP1305 $ (M.hmacGetDigest . M.hmac k) d

hashToKey :: Digest ChaChaPoly1305 -> SymmetricKey ChaChaPoly1305
hashToKey (DCCP1305 d) = SKCCP1305 $ convert d

hashToBytes :: Digest ChaChaPoly1305 -> ScrubbedBytes
hashToBytes (DCCP1305 d) = convert d

ctToBytes :: Ciphertext ChaChaPoly1305 -> ScrubbedBytes
ctToBytes (CTCCP1305 ct) = ct

bytesToCt :: ScrubbedBytes -> Ciphertext ChaChaPoly1305
bytesToCt = CTCCP1305
