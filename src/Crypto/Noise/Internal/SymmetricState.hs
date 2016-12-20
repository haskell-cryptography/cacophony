{-# LANGUAGE TemplateHaskell, ScopedTypeVariables #-}
{-# OPTIONS_HADDOCK hide #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.SymmetricState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.SymmetricState where

import Control.Arrow
import Control.Exception.Safe
import Control.Lens
import Data.ByteArray  (ScrubbedBytes, convert, length, replicate)
import Data.ByteString (empty)
import Data.Proxy
import Prelude hiding  (length, replicate)

import Crypto.Noise.Cipher
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState

data SymmetricState c h =
  SymmetricState { _ssCipher :: CipherState c
                 , _ssHasKey :: Bool
                 , _ssHasPSK :: Bool
                 , _ssck     :: ChainingKey h
                 , _ssh      :: Either ScrubbedBytes (Digest h)
                 , _ssk      :: ScrubbedBytes
                 }

$(makeLenses ''SymmetricState)

symmetricState :: forall c h. (Cipher c, Hash h)
               => ScrubbedBytes
               -> SymmetricState c h
symmetricState hsn = SymmetricState cs False False ck hsn' (convert empty)
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

mixPSK :: Hash h
       => ScrubbedBytes
       -> SymmetricState c h
       -> SymmetricState c h
mixPSK psk ss = ss'' & ssHasPSK .~ True
  where
    (ck, tmp) = hashHKDF (ss ^. ssck) psk
    ss'       = ss & ssck .~ ck
    ss''      = mixHash tmp ss'

mixHash :: Hash h
        => ScrubbedBytes
        -> SymmetricState c h
        -> SymmetricState c h
mixHash d ss = ss & ssh %~ Right . hash . (`mappend` d) . sshBytes

encryptAndHash :: (MonadThrow m, Cipher c, Hash h)
               => Plaintext
               -> SymmetricState c h
               -> m (ScrubbedBytes, SymmetricState c h)
encryptAndHash pt ss
  | ss ^. ssHasKey = mix . first toBytes <$> enc
  | otherwise      = return (pt, mixHash pt ss)
  where
    enc          = encryptAndIncrement (sshBytes (ss ^. ssh)) pt (ss ^. ssCipher)
    mix (cb, cs) = (cb, mixHash cb ss & ssCipher .~ cs)
    toBytes      = arr cipherTextToBytes

decryptAndHash :: (MonadThrow m, Cipher c, Hash h)
               => Ciphertext c
               -> SymmetricState c h
               -> m (Plaintext, SymmetricState c h)
decryptAndHash ct ss
  | ss ^. ssHasKey = second kss <$> dec
  | otherwise      = return (ct', mixHash ct' ss)
  where
    dec  = decryptAndIncrement (sshBytes (ss ^. ssh)) ct (ss ^. ssCipher)
    kss  = arr $ \cs -> mixHash ct' ss & ssCipher .~ cs
    ct'  = cipherTextToBytes ct

split :: (Cipher c, Hash h)
      => SymmetricState c h
      -> (CipherState c, CipherState c)
split ss = (cs1, cs2)
  where
    (cs1k, cs2k) = hashHKDF (ss ^. ssck) (ss ^. ssk)
    cs1k' = cipherBytesToSym . hashCKToBytes $ cs1k
    cs2k' = cipherBytesToSym cs2k
    cs1   = CipherState cs1k' cipherZeroNonce 0
    cs2   = CipherState cs2k' cipherZeroNonce 0

sshBytes :: Hash h
         => Either ScrubbedBytes (Digest h)
         -> ScrubbedBytes
sshBytes (Left  h) = h
sshBytes (Right h) = hashToBytes h
