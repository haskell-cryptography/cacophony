{-# LANGUAGE TypeFamilies #-}
-------------------------------------------------
-- |
-- Module      : Crypto.Noise.Cipher.AESGCM
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Cipher.AESGCM
  ( -- * Types
    AESGCM
  ) where

import Crypto.Error        (throwCryptoError)
import Crypto.Cipher.AES   (AES256)
import Crypto.Cipher.Types (AuthTag(..), AEADMode(AEAD_GCM), cipherInit,
                            aeadInit, aeadSimpleEncrypt, aeadSimpleDecrypt)
import Data.ByteArray      (ByteArray, Bytes, ScrubbedBytes, convert, take,
                            drop, length, copyAndFreeze, zero, append,
                            replicate)
import Data.Word           (Word8)
import Foreign.Ptr
import Foreign.Storable
import Prelude hiding      (drop, length, replicate, take)

import Crypto.Noise.Cipher

-- | Represents the AES256 cipher with GCM for AEAD.
data AESGCM

instance Cipher AESGCM where
  newtype Ciphertext   AESGCM = CTAES (AuthTag, ScrubbedBytes)
  newtype SymmetricKey AESGCM = SKAES ScrubbedBytes
  newtype Nonce        AESGCM = NAES  Bytes

  cipherName _      = "AESGCM"
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

encrypt :: SymmetricKey AESGCM
        -> Nonce AESGCM
        -> AssocData
        -> Plaintext
        -> Ciphertext AESGCM
encrypt (SKAES k) (NAES n) ad plaintext =
  CTAES $ aeadSimpleEncrypt aead ad plaintext 16
  where
    state = throwCryptoError . cipherInit $ k :: AES256
    aead  = throwCryptoError $ aeadInit AEAD_GCM state n

decrypt :: SymmetricKey AESGCM
        -> Nonce AESGCM
        -> AssocData
        -> Ciphertext AESGCM
        -> Maybe Plaintext
decrypt (SKAES k) (NAES n) ad (CTAES (authTag, ct)) =
  aeadSimpleDecrypt aead ad ct authTag
  where
    state = throwCryptoError . cipherInit $ k :: AES256
    aead  = throwCryptoError $ aeadInit AEAD_GCM state n

zeroNonce :: Nonce AESGCM
zeroNonce = NAES . zero $ 12

maxNonce :: Nonce AESGCM
maxNonce = NAES $ zero 4 `append` replicate 8 255

incNonce :: Nonce AESGCM
         -> Nonce AESGCM
incNonce (NAES n) = NAES $ ivAdd n 1

nonceEq :: Nonce AESGCM
        -> Nonce AESGCM
        -> Bool
nonceEq (NAES a) (NAES b) = a == b

nonceCmp :: Nonce AESGCM
         -> Nonce AESGCM
         -> Ordering
nonceCmp (NAES a) (NAES b) = compare a b

bytesToSym :: ScrubbedBytes
           -> SymmetricKey AESGCM
bytesToSym = SKAES . take 32

symToBytes :: SymmetricKey AESGCM
           -> ScrubbedBytes
symToBytes (SKAES sk) = sk

ctToBytes :: Ciphertext AESGCM
          -> ScrubbedBytes
ctToBytes (CTAES (a, ct)) = ct `mappend` convert a

bytesToCt :: ScrubbedBytes
          -> Ciphertext AESGCM
bytesToCt bytes =
  CTAES ( AuthTag . convert $ drop (length bytes - 16) bytes
        , take (length bytes - 16) bytes
        )

-- Adapted from cryptonite's Crypto.Cipher.Types.Block module.
ivAdd :: ByteArray b
      => b
      -> Int
      -> b
ivAdd b i = copy b
  where copy :: ByteArray bs => bs -> bs
        copy bs = copyAndFreeze bs $ loop i (length bs - 1)

        loop :: Int -> Int -> Ptr Word8 -> IO ()
        loop acc ofs p
            | ofs < 0   = return ()
            | otherwise = do
                v <- peek (p `plusPtr` ofs) :: IO Word8
                let accv    = acc + fromIntegral v
                    (hi,lo) = accv `divMod` 256
                poke (p `plusPtr` ofs) (fromIntegral lo :: Word8)
                loop hi (ofs - 1) p
