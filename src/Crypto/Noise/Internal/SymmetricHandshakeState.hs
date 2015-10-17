{-# LANGUAGE TemplateHaskell #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.SymmetricHandshakeState
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.SymmetricHandshakeState
  ( -- * Types
    SymmetricHandshakeState(SymmetricHandshakeState),
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
import Data.ByteString (empty)

import Crypto.Noise.Cipher
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Types

data SymmetricHandshakeState c =
  SymmetricHandshakeState { _shsCipher :: CipherState c
                          , _shsHasKey :: Bool
                          , _shsck     :: ChainingKey c
                          , _shsh      :: Digest c
                          }

$(makeLenses ''SymmetricHandshakeState)

symmetricHandshake :: Cipher c => ScrubbedBytes -> SymmetricHandshakeState c
symmetricHandshake hsn = SymmetricHandshakeState cs False ck h
  where
    h  = cipherHash $ convert hsn
    ck = cipherHashToCK h
    cs = CipherState (cipherHashToSK h) cipherZeroNonce

mixKey :: Cipher c => ScrubbedBytes -> SymmetricHandshakeState c -> SymmetricHandshakeState c
mixKey d shs = shs & shsCipher .~ cs
                   & shsHasKey .~ True
                   & shsck     .~ ck
  where
    (ck, k) = cipherHKDF (shs ^. shsck) d
    cs      = CipherState k cipherZeroNonce

mixHash :: Cipher c => ScrubbedBytes -> SymmetricHandshakeState c -> SymmetricHandshakeState c
mixHash d shs = shs & shsh %~ cipherHash . (`append` d) . cipherHashToBytes

encryptAndHash :: Cipher c => Plaintext -> SymmetricHandshakeState c -> (ScrubbedBytes, SymmetricHandshakeState c)
encryptAndHash (Plaintext pt) shs
  | shs ^. shsHasKey = (cipherTextToBytes ct, kshs)
  | otherwise = (pt, nkshs)
  where
    (ct, cs) = encryptAndIncrement (AssocData (cipherHashToBytes (shs ^. shsh))) (Plaintext pt) (shs ^. shsCipher)
    kshs     = mixHash (cipherTextToBytes ct) shs & shsCipher .~ cs
    nkshs    = mixHash pt shs

decryptAndHash :: Cipher c => Ciphertext c -> SymmetricHandshakeState c -> (Plaintext, SymmetricHandshakeState c)
decryptAndHash ct shs
  | shs ^. shsHasKey = (pt, kshs')
  | otherwise = (Plaintext (cipherTextToBytes ct), nkshs')
  where
    (pt, cs) = decryptAndIncrement (AssocData (cipherHashToBytes (shs ^. shsh))) ct (shs ^. shsCipher)
    kshs'    = mixHash (cipherTextToBytes ct) (shs & shsCipher .~ cs)
    nkshs'   = mixHash (cipherTextToBytes ct) shs

split :: Cipher c => SymmetricHandshakeState c -> (CipherState c, CipherState c)
split shs = (cs1, cs2)
  where
    (cs1k, cs2k) = cipherHKDF (shs ^. shsck) (convert empty)
    cs1  = CipherState (cipherChainToSym cs1k) cipherZeroNonce
    cs2  = CipherState cs2k cipherZeroNonce
