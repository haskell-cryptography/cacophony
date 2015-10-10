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

mixKey :: Cipher c => ScrubbedBytes -> SymmetricHandshakeState c -> SymmetricHandshakeState c
mixKey d shs@SymmetricHandshakeState{..} = shs { shsCipher = cs, shsHasKey = True }
  where
    gk   = cipherGetKey (csk shsCipher) (csn shsCipher)
    hmac = cipherHMAC gk d
    cs   = CipherState (cipherHashToKey hmac) cipherZeroNonce

mixHash :: Cipher c => ScrubbedBytes -> SymmetricHandshakeState c -> SymmetricHandshakeState c
mixHash d shs@SymmetricHandshakeState{..} =
  shs { shsh = cipherHash $ cipherHashToBytes shsh `append` d }

encryptAndHash :: Cipher c => Plaintext -> SymmetricHandshakeState c -> (ScrubbedBytes, SymmetricHandshakeState c)
encryptAndHash (Plaintext pt) shs@SymmetricHandshakeState{..}
  | shsHasKey = (cipherTextToBytes ct, kshs)
  | otherwise = (pt, nkshs)
  where
    (ct, cs) = encryptAndIncrement (AssocData (cipherHashToBytes shsh)) (Plaintext pt) shsCipher
    kshs     = mixHash (cipherTextToBytes ct) shs { shsCipher = cs }
    nkshs    = mixHash pt shs

decryptAndHash :: Cipher c => Ciphertext c -> SymmetricHandshakeState c -> (Plaintext, SymmetricHandshakeState c)
decryptAndHash ct shs@SymmetricHandshakeState{..}
  | shsHasKey = (pt, shs')
  | otherwise = (Plaintext (cipherTextToBytes ct), shs')
  where
    (pt, cs) = decryptAndIncrement (AssocData (cipherHashToBytes shsh)) ct shsCipher
    shs'     = mixHash (cipherTextToBytes ct) shs { shsCipher = cs }

split :: Cipher c => SymmetricHandshakeState c -> (CipherState c, CipherState c)
split SymmetricHandshakeState{..} = (cs1, cs2)
  where
    cs1k = cipherGetKey (csk shsCipher) (csn shsCipher)
    cs1  = CipherState { csk = cs1k, csn = cipherZeroNonce }
    cs2k = cipherGetKey (csk shsCipher) (cipherIncNonce (csn shsCipher))
    cs2  = CipherState { csk = cs2k, csn = cipherZeroNonce }
