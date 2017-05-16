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

import Crypto.Error                  (throwCryptoError)
import Crypto.Cipher.AES             (AES256)
import Crypto.Cipher.Types           (AuthTag(..), AEADMode(AEAD_GCM),
                                      cipherInit, aeadInit, aeadSimpleEncrypt,
                                      aeadSimpleDecrypt)
import Data.ByteArray                (ByteArray, ScrubbedBytes, convert)
import qualified Data.ByteArray as B (take, drop, length, copyAndFreeze)
import Data.Word                     (Word8)
import Foreign.Ptr
import Foreign.Storable

import Crypto.Noise.Cipher

-- | Represents the AES256 cipher with GCM for AEAD.
data AESGCM

instance Cipher AESGCM where
  newtype Ciphertext   AESGCM = CTAES (AuthTag, ScrubbedBytes)
  newtype SymmetricKey AESGCM = SKAES ScrubbedBytes
  newtype Nonce        AESGCM = NAES  ScrubbedBytes

  cipherName _      = "AESGCM"
  cipherEncrypt     = encrypt
  cipherDecrypt     = decrypt
  cipherNonce       = nonce
  cipherIncNonce    = incNonce
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

nonce :: Integer
      -> Nonce AESGCM
nonce i = NAES undefined

incNonce :: Nonce AESGCM
         -> Nonce AESGCM
incNonce (NAES n) = NAES $ ivAdd n 1

bytesToSym :: ScrubbedBytes
           -> SymmetricKey AESGCM
bytesToSym = SKAES . B.take 32

symToBytes :: SymmetricKey AESGCM
           -> ScrubbedBytes
symToBytes (SKAES sk) = sk

ctToBytes :: Ciphertext AESGCM
          -> ScrubbedBytes
ctToBytes (CTAES (a, ct)) = ct `mappend` convert a

bytesToCt :: ScrubbedBytes
          -> Ciphertext AESGCM
bytesToCt bytes =
  CTAES ( AuthTag . convert $ B.drop (B.length bytes - 16) bytes
        , B.take (B.length bytes - 16) bytes
        )

-- Adapted from cryptonite's Crypto.Cipher.Types.Block module:
-- https://github.com/haskell-crypto/cryptonite/blob/149bfa601081c27013811498fa507a83f5ce87ea/Crypto/Cipher/Types/Block.hs#L167
ivAdd :: ByteArray b => b -> Int -> b
ivAdd b i = copy b
  where copy :: ByteArray bs => bs -> bs
        copy bs = B.copyAndFreeze bs $ \p -> do
            let until0 accu = do
                  r <- loop accu (B.length bs - 1) p
                  case r of
                      0 -> return ()
                      _ -> until0 r
            until0 i

        loop :: Int -> Int -> Ptr Word8 -> IO Int
        loop 0   _   _ = return 0
        loop acc ofs p = do
            v <- peek (p `plusPtr` ofs) :: IO Word8
            let accv    = acc + fromIntegral v
                (hi,lo) = accv `divMod` 256
            poke (p `plusPtr` ofs) (fromIntegral lo :: Word8)
            if ofs == 0
                then return hi
                else loop hi (ofs - 1) p
