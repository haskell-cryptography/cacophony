{-# LANGUAGE TemplateHaskell #-}
--------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.CipherState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Internal.CipherState where

import Control.Exception.Safe
import Control.Lens

import Crypto.Noise.Cipher
import Crypto.Noise.Exception

data CipherState c =
  CipherState { _csk     :: Maybe (SymmetricKey c)
              , _csn     :: Nonce c
              } deriving Show

$(makeLenses ''CipherState)

-- | Creates a new CipherState with an optional symmetric key and a zero nonce.
cipherState :: Cipher c
            => Maybe (SymmetricKey c)
            -> CipherState c
cipherState sk = CipherState sk cipherZeroNonce

-- | Encrypts the provided plaintext and increments the nonce. If this
--   CipherState does not have a key associated with it, the plaintext
--   will be returned.
encryptWithAd :: (MonadThrow m, Cipher c)
              => AssocData
              -> Plaintext
              -> CipherState c
              -> m (Ciphertext c, CipherState c)
encryptWithAd ad plaintext cs
  | validNonce cs = return (result, newState)
  | otherwise     = throwM $ MessageLimitReached "encryptWithAd"
  where
    result = maybe (cipherBytesToText plaintext)
                   (\k -> cipherEncrypt k (cs ^. csn) ad plaintext)
                   $ cs ^. csk
    newState = cs & csn %~ cipherIncNonce

-- | Decrypts the provided ciphertext and increments the nonce. If this
--   CipherState does not have a key associated with it, the ciphertext
--   will be returned. If the CipherState does have a key and decryption
--   fails, a @DecryptionError@ will be returned.
decryptWithAd :: (MonadThrow m, Cipher c)
              => AssocData
              -> Ciphertext c
              -> CipherState c
              -> m (Plaintext, CipherState c)
decryptWithAd ad ct cs
  | validNonce cs =
    maybe (throwM (DecryptionError "decryptWithAd"))
          (\x -> return (x, newState))
          result
  | otherwise     = throwM $ MessageLimitReached "decryptWithAd"
  where
    result   = maybe (Just . cipherTextToBytes $ ct)
                     (\k -> cipherDecrypt k (cs ^. csn) ad ct)
                     $ cs ^. csk
    newState = cs & csn %~ cipherIncNonce

-- | Rekeys the CipherState. If a key has not been established yet, the
--   CipherState is returned unmodified.
rekey :: Cipher c
      => CipherState c
      -> CipherState c
rekey cs = cs & csk %~ (<*>) (pure cipherRekey)

-- | Tests whether the Nonce contained within a CipherState is valid (less
--   than the maximum allowed).
validNonce :: Cipher c
           => CipherState c
           -> Bool
validNonce cs = cs ^. csn < cipherMaxNonce
