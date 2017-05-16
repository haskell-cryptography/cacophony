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

import           Crypto.Error   (throwCryptoError)
import qualified Crypto.Cipher.ChaChaPoly1305 as CCP
import qualified Crypto.MAC.Poly1305          as P
import           Data.ByteArray (ScrubbedBytes, convert, take, drop, length)
import qualified Data.ByteString              as BS (replicate)
import           Prelude hiding (take, drop, length)

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
  cipherIncNonce    = incNonce
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
    constant = BS.replicate 4 0
    iv       = BS.replicate 8 0

incNonce :: Nonce ChaChaPoly1305 -> Nonce ChaChaPoly1305
incNonce (NCCP1305 n) = NCCP1305 $ CCP.incrementNonce n

bytesToSym :: ScrubbedBytes -> SymmetricKey ChaChaPoly1305
bytesToSym = SKCCP1305 . take 32

symToBytes :: SymmetricKey ChaChaPoly1305 -> ScrubbedBytes
symToBytes (SKCCP1305 sk) = sk

ctToBytes :: Ciphertext ChaChaPoly1305 -> ScrubbedBytes
ctToBytes (CTCCP1305 (ct, a)) = ct `mappend` convert a

bytesToCt :: ScrubbedBytes -> Ciphertext ChaChaPoly1305
bytesToCt bytes =
  CTCCP1305 (take (length bytes - 16) bytes
            , P.Auth . convert $ drop (length bytes - 16) bytes
            )
