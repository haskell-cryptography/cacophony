{-# LANGUAGE TemplateHaskell #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.CipherState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.CipherState
  ( -- * Types
    CipherState(CipherState),
    -- * Lenses
    csk,
    csn,
    -- * Functions
    encryptAndIncrement,
    decryptAndIncrement
  ) where

import Control.Lens
import Data.Maybe (fromMaybe)

import Crypto.Noise.Cipher

-- | Represents a symmetric key and associated nonce.
data CipherState c =
  CipherState { _csk :: SymmetricKey c
              , _csn :: Nonce c
              }

$(makeLenses ''CipherState)

encryptAndIncrement :: Cipher c => AssocData -> Plaintext -> CipherState c -> (Ciphertext c, CipherState c)
encryptAndIncrement ad plaintext cs = (ct, newState)
  where
    ct       = cipherEncrypt (cs ^. csk) (cs ^. csn) ad plaintext
    newState = cs & csn %~ cipherIncNonce

decryptAndIncrement :: Cipher c => AssocData -> Ciphertext c -> CipherState c -> (Plaintext, CipherState c)
decryptAndIncrement ad ct cs = (pt, newState)
  where
    pt       = fromMaybe (error "decryptAndIncrement: error decrypting ciphertext")
                         (cipherDecrypt (cs ^. csk) (cs ^. csn) ad ct)
    newState = cs & csn %~ cipherIncNonce
