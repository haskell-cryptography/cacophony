{-# LANGUAGE TemplateHaskell #-}
{-# OPTIONS_HADDOCK hide #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.CipherState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.CipherState where

import Control.Exception.Safe
import Control.Lens

import Crypto.Noise.Cipher
import Crypto.Noise.Internal.Types

data CipherState c =
  CipherState { _csk     :: SymmetricKey c
              , _csn     :: Nonce c
              , _csCount :: Integer
              } deriving Show

$(makeLenses ''CipherState)

encryptAndIncrement :: (MonadThrow m, Cipher c)
                    => AssocData
                    -> Plaintext
                    -> CipherState c
                    -> m (Ciphertext c, CipherState c)
encryptAndIncrement ad plaintext cs
  | allow     = return (ct, newState)
  | otherwise = throwM $ MessageLimitReached "encryptAndIncrement"
  where
    ct       = cipherEncrypt (cs ^. csk) (cs ^. csn) ad plaintext
    newState = cs & csn %~ cipherIncNonce
    allow    = cs ^. csCount < 2 ^ (64 :: Integer)

decryptAndIncrement :: (MonadThrow m, Cipher c)
                    => AssocData
                    -> Ciphertext c
                    -> CipherState c
                    -> m (Plaintext, CipherState c)
decryptAndIncrement ad ct cs
  | allow     =
    maybe (throwM (DecryptionError "decryptAndIncrement"))
          (\x -> return (x, newState))
          pt
  | otherwise = throwM $ MessageLimitReached "decryptAndIncrement"
  where
    pt       = cipherDecrypt (cs ^. csk) (cs ^. csn) ad ct
    newState = maybe cs (const (cs & csn %~ cipherIncNonce)) pt
    allow    = cs ^. csCount < 2 ^ (64 :: Integer)
