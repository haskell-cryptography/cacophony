{-# LANGUAGE TemplateHaskell #-}
{-# OPTIONS_HADDOCK hide #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.CipherState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.CipherState where

import Control.Lens

import Crypto.Noise.Cipher

data CipherState c =
  CipherState { _csk :: SymmetricKey c
              , _csn :: Nonce c
              } deriving Show

$(makeLenses ''CipherState)

encryptAndIncrement :: Cipher c
                    => AssocData
                    -> Plaintext
                    -> CipherState c
                    -> (Ciphertext c, CipherState c)
encryptAndIncrement ad plaintext cs = (ct, newState)
  where
    ct       = cipherEncrypt (cs ^. csk) (cs ^. csn) ad plaintext
    newState = cs & csn %~ cipherIncNonce

decryptAndIncrement :: Cipher c
                    => AssocData
                    -> Ciphertext c
                    -> CipherState c
                    -> Maybe (Plaintext, CipherState c)
decryptAndIncrement ad ct cs =
  maybe Nothing
        (\x -> Just (x, newState))
        pt
  where
    pt       = cipherDecrypt (cs ^. csk) (cs ^. csn) ad ct
    newState = maybe cs (const (cs & csn %~ cipherIncNonce)) pt
