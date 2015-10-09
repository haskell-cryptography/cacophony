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

encryptAndIncrement :: Cipher c => CipherState c -> AssocData -> Plaintext -> (Ciphertext c, CipherState c)
encryptAndIncrement cs@CipherState{..} ad plaintext = (ct, newState)
  where
    ct       = cipherEncrypt csk csn ad plaintext
    newState = cs { csn = cipherIncNonce csn }

decryptAndIncrement :: Cipher c => CipherState c -> AssocData -> Ciphertext c -> (Plaintext, CipherState c)
decryptAndIncrement cs@CipherState{..} ad ct = (pt, newState)
  where
    pt       = fromJust $ cipherDecrypt csk csn ad ct
    newState = cs { csn = cipherIncNonce csn }
