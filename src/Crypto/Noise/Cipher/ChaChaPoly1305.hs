{-# LANGUAGE TypeFamilies #-}
---------------------------------------------------
-- |
-- Module      : Crypto.Noise.Cipher.ChaChaPoly1305
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Cipher.ChaChaPoly1305
  ( -- * Types
    ChaChaPoly1305
  ) where

import           Crypto.Error    (throwCryptoError)
import qualified Crypto.Cipher.ChaChaPoly1305 as CCP
import qualified Crypto.MAC.Poly1305          as P
import           Data.ByteArray  (ScrubbedBytes, Bytes, convert, take, drop,
                                  length, replicate, constEq)
import           Data.ByteString (ByteString, reverse)
import           Prelude hiding  (drop, length, replicate, take, reverse)

import Crypto.Noise.Cipher

-- | Represents the ChaCha cipher with Poly1305 for AEAD.
data ChaChaPoly1305

instance Cipher ChaChaPoly1305 where
  newtype Ciphertext   ChaChaPoly1305 = CTCCP1305 (ScrubbedBytes, P.Auth)
  newtype SymmetricKey ChaChaPoly1305 = SKCCP1305 ScrubbedBytes
  newtype Nonce        ChaChaPoly1305 = NCCP1305  CCP.Nonce

  cipherName _      = "ChaChaPoly"
  cipherEncrypt     = encrypt
  cipherDecrypt     = decrypt
  cipherZeroNonce   = zeroNonce
  cipherMaxNonce    = maxNonce
  cipherIncNonce    = incNonce
  cipherNonceEq     = nonceEq
  cipherNonceCmp    = nonceCmp
  cipherBytesToSym  = bytesToSym
  cipherSymToBytes  = symToBytes
  cipherTextToBytes = ctToBytes
  cipherBytesToText = bytesToCt

encrypt :: SymmetricKey ChaChaPoly1305
        -> Nonce ChaChaPoly1305
        -> AssocData
        -> Plaintext
        -> Ciphertext ChaChaPoly1305
encrypt (SKCCP1305 k) (NCCP1305 n) ad plaintext =
  CTCCP1305 (out, P.Auth (convert authTag))
  where
    initState       = throwCryptoError $ CCP.initialize k n
    afterAAD        = CCP.finalizeAAD (CCP.appendAAD ad initState)
    (out, afterEnc) = CCP.encrypt plaintext afterAAD
    authTag         = CCP.finalize afterEnc

decrypt :: SymmetricKey ChaChaPoly1305
        -> Nonce ChaChaPoly1305
        -> AssocData
        -> Ciphertext ChaChaPoly1305
        -> Maybe Plaintext
decrypt (SKCCP1305 k) (NCCP1305 n) ad (CTCCP1305 (ct, auth)) =
  if auth == calcAuthTag
    then return out
    else Nothing
  where
    initState       = throwCryptoError $ CCP.initialize k n
    afterAAD        = CCP.finalizeAAD (CCP.appendAAD ad initState)
    (out, afterDec) = CCP.decrypt ct afterAAD
    calcAuthTag     = CCP.finalize afterDec

zeroNonce :: Nonce ChaChaPoly1305
zeroNonce = NCCP1305 . throwCryptoError $ CCP.nonce8 constant iv
  where
    constant = replicate 4 0 :: Bytes
    iv       = replicate 8 0 :: Bytes

maxNonce :: Nonce ChaChaPoly1305
maxNonce = NCCP1305 . throwCryptoError $ CCP.nonce8 constant iv
  where
    constant = replicate 4 0   :: Bytes
    iv       = replicate 8 255 :: Bytes

incNonce :: Nonce ChaChaPoly1305
         -> Nonce ChaChaPoly1305
incNonce (NCCP1305 n) = NCCP1305 $ CCP.incrementNonce n

nonceEq :: Nonce ChaChaPoly1305
        -> Nonce ChaChaPoly1305
        -> Bool
nonceEq (NCCP1305 a) (NCCP1305 b) = constEq a b

-- | Since nonces in this cipher are little endian, they must be reversed prior
--   to comparison. A ByteString was chosen because it uses memcmp under the
--   hood.
nonceCmp :: Nonce ChaChaPoly1305
         -> Nonce ChaChaPoly1305
         -> Ordering
nonceCmp (NCCP1305 a) (NCCP1305 b) = compare (reverse (convert a :: ByteString))
                                             (reverse (convert b :: ByteString))

bytesToSym :: ScrubbedBytes
           -> SymmetricKey ChaChaPoly1305
bytesToSym = SKCCP1305 . take 32

symToBytes :: SymmetricKey ChaChaPoly1305
           -> ScrubbedBytes
symToBytes (SKCCP1305 sk) = sk

ctToBytes :: Ciphertext ChaChaPoly1305
          -> ScrubbedBytes
ctToBytes (CTCCP1305 (ct, a)) = ct `mappend` convert a

bytesToCt :: ScrubbedBytes
          -> Ciphertext ChaChaPoly1305
bytesToCt bytes =
  CTCCP1305 (take (length bytes - 16) bytes
            , P.Auth . convert $ drop (length bytes - 16) bytes
            )
