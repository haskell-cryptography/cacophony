{-# LANGUAGE RecordWildCards #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.CipherState
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.CipherState
  ( -- * Types
    CipherState(..),
    -- * Functions
    encryptAndIncrement,
    decryptAndIncrement
  ) where

import Data.Maybe (fromJust)

import Crypto.Noise.Cipher

data CipherState c =
  CipherState { csk :: SymmetricKey c
              , csn :: Nonce c
              }

encryptAndIncrement :: Cipher c => AssocData -> Plaintext -> CipherState c -> (Ciphertext c, CipherState c)
encryptAndIncrement ad plaintext cs@CipherState{..} = (ct, newState)
  where
    ct       = cipherEncrypt csk csn ad plaintext
    newState = cs { csn = cipherIncNonce csn }

decryptAndIncrement :: Cipher c => AssocData -> Ciphertext c -> CipherState c -> (Plaintext, CipherState c)
decryptAndIncrement ad ct cs@CipherState{..} = (pt, newState)
  where
    pt       = fromJust $ cipherDecrypt csk csn ad ct
    newState = cs { csn = cipherIncNonce csn }
