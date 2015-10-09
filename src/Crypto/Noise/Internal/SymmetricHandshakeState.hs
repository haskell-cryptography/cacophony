{-# LANGUAGE RecordWildCards #-}

----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.SymmetricHandshakeState
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.SymmetricHandshakeState
  ( -- * Types
    SymmetricHandshakeState(..),
    -- * Functions
    symmetricHandshake,
    mixKey,
    mixHash,
    encryptAndHash,
    decryptAndHash,
    split
  ) where

import Crypto.Noise.Cipher
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Types

data SymmetricHandshakeState c =
  SymmetricHandshakeState { shsCipher :: CipherState c
                          , shsHasKey :: Bool
                          , shsh      :: Digest c
                          }

symmetricHandshake :: Cipher c => ScrubbedBytes -> SymmetricHandshakeState c
symmetricHandshake hsn = SymmetricHandshakeState cs False h
  where
    h  = cipherHash $ convert hsn
    cs = CipherState (cipherHashToKey h) cipherZeroNonce

mixKey :: Cipher c => SymmetricHandshakeState c -> ScrubbedBytes -> SymmetricHandshakeState c
mixKey shs@SymmetricHandshakeState{..} d = shs { shsCipher = cs, shsHasKey = True }
  where
    gk   = cipherGetKey (csk shsCipher) (csn shsCipher)
    hmac = cipherHMAC gk d
    cs   = CipherState (cipherHashToKey hmac) cipherZeroNonce

mixHash :: Cipher c => SymmetricHandshakeState c -> ScrubbedBytes -> SymmetricHandshakeState c
mixHash shs@SymmetricHandshakeState{..} d =
  shs { shsh = cipherHash $ cipherHashToBytes shsh `append` d }

encryptAndHash :: Cipher c => SymmetricHandshakeState c -> Plaintext -> (ScrubbedBytes, SymmetricHandshakeState c)
encryptAndHash shs@SymmetricHandshakeState{..} (Plaintext pt)
  | shsHasKey = (cipherTextToBytes ct, kshs)
  | otherwise = (pt, nkshs)
  where
    (ct, cs) = encryptAndIncrement shsCipher (AssocData (cipherHashToBytes shsh)) (Plaintext pt)
    kshs     = mixHash shs { shsCipher = cs } (cipherTextToBytes ct)
    nkshs    = mixHash shs pt

decryptAndHash :: Cipher c => SymmetricHandshakeState c -> Ciphertext c -> (Plaintext, SymmetricHandshakeState c)
decryptAndHash shs@SymmetricHandshakeState{..} ct
  | shsHasKey = (pt, shs')
  | otherwise = (Plaintext (cipherTextToBytes ct), shs')
  where
    (pt, cs) = decryptAndIncrement shsCipher (AssocData (cipherHashToBytes shsh)) ct
    shs'     = mixHash shs { shsCipher = cs } (cipherTextToBytes ct)

split :: Cipher c => SymmetricHandshakeState c -> (CipherState c, CipherState c)
split SymmetricHandshakeState{..} = (cs1, cs2)
  where
    cs1k = cipherGetKey (csk shsCipher) (csn shsCipher)
    cs1  = CipherState { csk = cs1k, csn = cipherZeroNonce }
    cs2k = cipherGetKey (csk shsCipher) (cipherIncNonce (csn shsCipher))
    cs2  = CipherState { csk = cs2k, csn = cipherZeroNonce }
