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
import qualified Data.ByteArray as B (take, drop, length)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS (replicate)

import Crypto.Noise.Cipher
import Crypto.Noise.Types

data ChaChaPoly1305

instance Cipher ChaChaPoly1305 where
  newtype Ciphertext   ChaChaPoly1305 = CTCCP1305 (ScrubbedBytes, P.Auth)
  newtype SymmetricKey ChaChaPoly1305 = SKCCP1305 ScrubbedBytes
  newtype ChainingKey  ChaChaPoly1305 = CKCCP1305 ScrubbedBytes
  newtype Nonce        ChaChaPoly1305 = NCCP1305  CCP.Nonce
  newtype Digest       ChaChaPoly1305 = DCCP1305  (H.Digest H.SHA256)

  cipherName _      = convert ("ChaChaPoly" :: ByteString)
  cipherEncrypt     = encrypt
  cipherDecrypt     = decrypt
  cipherZeroNonce   = zeroNonce
  cipherIncNonce    = incNonce
  cipherHash        = hash
  cipherHKDF        = hkdf
  cipherHashToSK    = hashToSK
  cipherHashToCK    = hashToCK
  cipherChainToSym  = chainToSym
  cipherHashToBytes = hashToBytes
  cipherTextToBytes = ctToBytes
  cipherBytesToText = bytesToCt

encrypt :: SymmetricKey ChaChaPoly1305 -> Nonce ChaChaPoly1305 -> AssocData -> Plaintext -> Ciphertext ChaChaPoly1305
encrypt (SKCCP1305 k) (NCCP1305 n) (AssocData ad) (Plaintext plaintext) =
  CTCCP1305 (out, P.Auth (convert authTag))
  where
    initState       = throwCryptoError $ CCP.initialize k n
    afterAAD        = CCP.finalizeAAD (CCP.appendAAD ad initState)
    (out, afterEnc) = CCP.encrypt plaintext afterAAD
    authTag         = CCP.finalize afterEnc

decrypt :: SymmetricKey ChaChaPoly1305 -> Nonce ChaChaPoly1305 -> AssocData -> Ciphertext ChaChaPoly1305 -> Maybe Plaintext
decrypt (SKCCP1305 k) (NCCP1305 n) (AssocData ad) (CTCCP1305 (ct, auth)) =
  if auth == calcAuthTag then
    return $ Plaintext out
  else
    Nothing
  where
    initState       = throwCryptoError $ CCP.initialize k n
    afterAAD        = CCP.finalizeAAD (CCP.appendAAD ad initState)
    (out, afterDec) = CCP.decrypt ct afterAAD
    calcAuthTag     = CCP.finalize afterDec

zeroNonce :: Nonce ChaChaPoly1305
zeroNonce = NCCP1305 . throwCryptoError $ CCP.nonce8 constant iv
  where
    constant = BS.replicate 4 0
    iv       = BS.replicate 8 0

incNonce :: Nonce ChaChaPoly1305 -> Nonce ChaChaPoly1305
incNonce (NCCP1305 n) = NCCP1305 $ CCP.incrementNonce n

hash :: ScrubbedBytes -> Digest ChaChaPoly1305
hash bs = DCCP1305 $ H.hash bs

hkdf :: ChainingKey ChaChaPoly1305 -> ScrubbedBytes -> (ChainingKey ChaChaPoly1305, SymmetricKey ChaChaPoly1305)
hkdf (CKCCP1305 ck) d = (CKCCP1305 ck', SKCCP1305 sk)
  where
    x01   = convert ("\x01" :: ByteString) :: ScrubbedBytes
    x02   = convert ("\x02" :: ByteString) :: ScrubbedBytes

    hmac1 = M.hmac ck d :: M.HMAC H.SHA256
    temp  = convert . M.hmacGetDigest $ hmac1 :: ScrubbedBytes
    hmac2 = M.hmac temp x01 :: M.HMAC H.SHA256
    hmac3 = M.hmac temp (convert hmac2 `append` x02) :: M.HMAC H.SHA256
    ck'   = convert . M.hmacGetDigest $ hmac2
    sk    = convert . M.hmacGetDigest $ hmac3

chainToSym :: ChainingKey ChaChaPoly1305 -> SymmetricKey ChaChaPoly1305
chainToSym (CKCCP1305 ck) = SKCCP1305 . convert $ ck

hashToSK :: Digest ChaChaPoly1305 -> SymmetricKey ChaChaPoly1305
hashToSK (DCCP1305 d) = SKCCP1305 . convert $ d

hashToCK :: Digest ChaChaPoly1305 -> ChainingKey ChaChaPoly1305
hashToCK (DCCP1305 d) = CKCCP1305 . convert $ d

hashToBytes :: Digest ChaChaPoly1305 -> ScrubbedBytes
hashToBytes (DCCP1305 d) = convert d

ctToBytes :: Ciphertext ChaChaPoly1305 -> ScrubbedBytes
ctToBytes (CTCCP1305 (ct, a)) = ct `append` convert a

bytesToCt :: ScrubbedBytes -> Ciphertext ChaChaPoly1305
bytesToCt bytes =
  CTCCP1305 (B.take (B.length bytes - 16) bytes
            , P.Auth . convert $ B.drop (B.length bytes - 16) bytes
            )
