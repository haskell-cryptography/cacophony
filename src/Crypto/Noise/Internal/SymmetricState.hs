{-# LANGUAGE TemplateHaskell, ScopedTypeVariables #-}
{-# OPTIONS_HADDOCK hide #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.SymmetricState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.SymmetricState where

import Control.Lens
import Data.ByteString (empty)
import Data.Proxy
import Prelude hiding  (length, replicate)

import Crypto.Noise.Cipher
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.Types
import Data.ByteArray.Extend

data SymmetricState c h =
  SymmetricState { _ssCipher :: CipherState c
                 , _ssHasKey :: Bool
                 , _ssHasPSK :: Bool
                 , _ssck     :: ChainingKey h
                 , _ssh      :: Either ScrubbedBytes (Digest h)
                 }

$(makeLenses ''SymmetricState)

symmetricState :: forall c h. (Cipher c, Hash h)
               => ScrubbedBytes
               -> SymmetricState c h
symmetricState hsn = SymmetricState cs False False ck hsn'
  where
    hashLen    = hashLength (Proxy :: Proxy h)
    shouldHash = length hsn > hashLen
    hsn'       = if shouldHash
                   then Right $ hash hsn
                   else Left $ hsn `mappend` replicate (hashLen - length hsn) 0
    ck         = hashBytesToCK . sshBytes $ hsn'
    cs         = CipherState undefined undefined 0

mixKey :: (Cipher c, Hash h)
       => ScrubbedBytes
       -> SymmetricState c h
       -> SymmetricState c h
mixKey d ss = ss & ssCipher .~ cs
                 & ssHasKey .~ True
                 & ssck     .~ ck
  where
    (ck, k) = hashHKDF (ss ^. ssck) d
    cs      = CipherState (cipherBytesToSym k) cipherZeroNonce 0

mixPSK :: (Cipher c, Hash h)
       => ScrubbedBytes
       -> SymmetricState c h
       -> SymmetricState c h
mixPSK psk ss = ss'' & ssHasPSK .~ True
  where
    (ck, tmp) = hashHKDF (ss ^. ssck) psk
    ss'       = ss & ssck .~ ck
    ss''      = mixHash tmp ss'

mixHash :: (Cipher c, Hash h)
        => ScrubbedBytes
        -> SymmetricState c h
        -> SymmetricState c h
mixHash d ss = ss & ssh %~ Right . hash . (`mappend` d) . sshBytes

encryptAndHash :: (Cipher c, Hash h)
               => Plaintext
               -> SymmetricState c h
               -> Either NoiseException (ScrubbedBytes, SymmetricState c h)
encryptAndHash pt ss
  | ss ^. ssHasKey = either Left (\(ct, cs') -> Right (cipherTextToBytes ct, kss ct cs')) enc
  | otherwise      = Right (pt, nkss)
  where
    enc       = encryptAndIncrement (sshBytes (ss ^. ssh)) pt (ss ^. ssCipher)
    kss ct cs = mixHash (cipherTextToBytes ct) ss & ssCipher .~ cs
    nkss      = mixHash pt ss

decryptAndHash :: (Cipher c, Hash h)
               => Ciphertext c
               -> SymmetricState c h
               -> Either NoiseException (Plaintext, SymmetricState c h)
decryptAndHash ct ss
  | ss ^. ssHasKey = either Left (\(pt, cs') -> Right (pt, kss cs')) dec
  | otherwise      = Right (cipherTextToBytes ct, nkss)
  where
    dec    = decryptAndIncrement (sshBytes (ss ^. ssh)) ct (ss ^. ssCipher)
    kss cs = mixHash (cipherTextToBytes ct) ss & ssCipher .~ cs
    nkss   = mixHash (cipherTextToBytes ct) ss

split :: (Cipher c, Hash h)
      => SymmetricState c h
      -> (CipherState c, CipherState c)
split ss = (cs1, cs2)
  where
    (cs1k, cs2k) = hashHKDF (ss ^. ssck) (convert empty)
    cs1k' = cipherBytesToSym . hashCKToBytes $ cs1k
    cs2k' = cipherBytesToSym cs2k
    cs1   = CipherState cs1k' cipherZeroNonce 0
    cs2   = CipherState cs2k' cipherZeroNonce 0

sshBytes :: Hash h
         => Either ScrubbedBytes (Digest h)
         -> ScrubbedBytes
sshBytes (Left  h) = h
sshBytes (Right h) = hashToBytes h
