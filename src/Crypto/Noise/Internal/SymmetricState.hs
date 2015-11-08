{-# LANGUAGE TemplateHaskell, FlexibleContexts, ScopedTypeVariables #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.SymmetricState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.SymmetricState
  ( -- * Types
    SymmetricState(SymmetricState),
    -- * Lenses
    shsCipher,
    shsHasKey,
    shsh,
    -- * Functions
    symmetricHandshake,
    mixKey,
    mixHash,
    encryptAndHash,
    decryptAndHash,
    split
  ) where

import Control.Lens
import Data.ByteArray as BA (length, replicate)
import Data.ByteString (empty)
import Data.Proxy

import Crypto.Noise.Cipher
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Types

data SymmetricState c h =
  SymmetricState { _shsCipher :: CipherState c
                 , _shsHasKey :: Bool
                 , _shsck     :: ChainingKey h
                 , _shsh      :: Either ScrubbedBytes (Digest h)
                 }

$(makeLenses ''SymmetricState)

symmetricHandshake :: forall c h. (Cipher c, Hash h) => ScrubbedBytes -> SymmetricState c h
symmetricHandshake hsn = SymmetricState cs False ck hsn'
  where
    hashLen    = hashLength (Proxy :: Proxy h)
    shouldHash = BA.length hsn > hashLen
    hsn'       = if shouldHash then
                   Left $ hsn `append` BA.replicate (hashLen - BA.length hsn) 0
                 else
                   Right $ hash hsn
    ck         = hashBytesToCK . shshBytes $ hsn'
    cs         = CipherState undefined undefined

mixKey :: (Cipher c, Hash h) => ScrubbedBytes -> SymmetricState c h -> SymmetricState c h
mixKey d shs = shs & shsCipher .~ cs
                   & shsHasKey .~ True
                   & shsck     .~ ck
  where
    (ck, k) = hashHKDF (shs ^. shsck) d
    cs      = CipherState (cipherBytesToSym k) cipherZeroNonce

mixHash :: (Cipher c, Hash h) => ScrubbedBytes -> SymmetricState c h -> SymmetricState c h
mixHash d shs = shs & shsh %~ Right . hash . (`append` d) . shshBytes

encryptAndHash :: (Cipher c, Hash h) => Plaintext -> SymmetricState c h -> (ScrubbedBytes, SymmetricState c h)
encryptAndHash (Plaintext pt) shs
  | shs ^. shsHasKey = (cipherTextToBytes ct, kshs)
  | otherwise = (pt, nkshs)
  where
    (ct, cs) = encryptAndIncrement (AssocData (shshBytes (shs ^. shsh))) (Plaintext pt) (shs ^. shsCipher)
    kshs     = mixHash (cipherTextToBytes ct) shs & shsCipher .~ cs
    nkshs    = mixHash pt shs

decryptAndHash :: (Cipher c, Hash h) => Ciphertext c -> SymmetricState c h -> (Plaintext, SymmetricState c h)
decryptAndHash ct shs
  | shs ^. shsHasKey = (pt, kshs')
  | otherwise = (Plaintext (cipherTextToBytes ct), nkshs')
  where
    (pt, cs) = decryptAndIncrement (AssocData (shshBytes (shs ^. shsh))) ct (shs ^. shsCipher)
    kshs'    = mixHash (cipherTextToBytes ct) (shs & shsCipher .~ cs)
    nkshs'   = mixHash (cipherTextToBytes ct) shs

split :: (Cipher c, Hash h) => SymmetricState c h -> (CipherState c, CipherState c)
split shs = (cs1, cs2)
  where
    (cs1k, cs2k) = hashHKDF (shs ^. shsck) (convert empty)
    cs1k' = cipherBytesToSym . hashCKToBytes $ cs1k
    cs2k' = cipherBytesToSym cs2k
    cs1   = CipherState cs1k' cipherZeroNonce
    cs2   = CipherState cs2k' cipherZeroNonce

shshBytes :: Hash h => Either ScrubbedBytes (Digest h) -> ScrubbedBytes
shshBytes (Left  h) = h
shshBytes (Right h) = hashToBytes h
