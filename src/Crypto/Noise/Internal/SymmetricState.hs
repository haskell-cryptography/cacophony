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
    ssCipher,
    ssHasKey,
    ssh,
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
  SymmetricState { _ssCipher :: CipherState c
                 , _ssHasKey :: Bool
                 , _ssck     :: ChainingKey h
                 , _ssh      :: Either ScrubbedBytes (Digest h)
                 }

$(makeLenses ''SymmetricState)

symmetricHandshake :: forall c h. (Cipher c, Hash h) => ScrubbedBytes -> SymmetricState c h
symmetricHandshake hsn = SymmetricState cs False ck hsn'
  where
    hashLen    = hashLength (Proxy :: Proxy h)
    shouldHash = BA.length hsn > hashLen
    hsn'       = if shouldHash then
                   Right $ hash hsn
                 else
                   Left $ hsn `append` BA.replicate (hashLen - BA.length hsn) 0
    ck         = hashBytesToCK . sshBytes $ hsn'
    cs         = CipherState undefined undefined

mixKey :: (Cipher c, Hash h) => ScrubbedBytes -> SymmetricState c h -> SymmetricState c h
mixKey d ss = ss & ssCipher .~ cs
                 & ssHasKey .~ True
                 & ssck     .~ ck
  where
    (ck, k) = hashHKDF (ss ^. ssck) d
    cs      = CipherState (cipherBytesToSym k) cipherZeroNonce

mixHash :: (Cipher c, Hash h) => ScrubbedBytes -> SymmetricState c h -> SymmetricState c h
mixHash d ss = ss & ssh %~ Right . hash . (`append` d) . sshBytes

encryptAndHash :: (Cipher c, Hash h) => Plaintext -> SymmetricState c h -> (ScrubbedBytes, SymmetricState c h)
encryptAndHash (Plaintext pt) ss
  | ss ^. ssHasKey = (cipherTextToBytes ct, kss)
  | otherwise      = (pt, nkss)
  where
    (ct, cs) = encryptAndIncrement (AssocData (sshBytes (ss ^. ssh))) (Plaintext pt) (ss ^. ssCipher)
    kss      = mixHash (cipherTextToBytes ct) ss & ssCipher .~ cs
    nkss     = mixHash pt ss

decryptAndHash :: (Cipher c, Hash h) => Ciphertext c -> SymmetricState c h -> (Plaintext, SymmetricState c h)
decryptAndHash ct ss
  | ss ^. ssHasKey = (pt, kss)
  | otherwise      = (Plaintext (cipherTextToBytes ct), nkss)
  where
    (pt, cs) = decryptAndIncrement (AssocData (sshBytes (ss ^. ssh))) ct (ss ^. ssCipher)
    kss      = mixHash (cipherTextToBytes ct) ss & ssCipher .~ cs
    nkss     = mixHash (cipherTextToBytes ct) ss

split :: (Cipher c, Hash h) => SymmetricState c h -> (CipherState c, CipherState c)
split ss = (cs1, cs2)
  where
    (cs1k, cs2k) = hashHKDF (ss ^. ssck) (convert empty)
    cs1k' = cipherBytesToSym . hashCKToBytes $ cs1k
    cs2k' = cipherBytesToSym cs2k
    cs1   = CipherState cs1k' cipherZeroNonce
    cs2   = CipherState cs2k' cipherZeroNonce

sshBytes :: Hash h => Either ScrubbedBytes (Digest h) -> ScrubbedBytes
sshBytes (Left  h) = h
sshBytes (Right h) = hashToBytes h
