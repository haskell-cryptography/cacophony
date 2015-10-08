{-# LANGUAGE RecordWildCards #-}

----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.SymmetricHandshakeState
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.SymmetricHandshakeState
  ( -- * Types
    SymmetricHandshakeState,
    -- * Functions
    symmetricHandshake,
    mixKey,
    mixHash,
    encryptAndHash,
    decryptAndHash,
    split
  ) where

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
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
  shs { shsh = cipherHash $ (cipherHashToBytes shsh) `append` d }

encryptAndHash :: Cipher c => SymmetricHandshakeState c -> Plaintext -> (ScrubbedBytes, SymmetricHandshakeState c)
encryptAndHash shs@SymmetricHandshakeState{..} (Plaintext pt)
  | shsHasKey = (cipherTextToBytes ct, kshs)
  | otherwise = (pt, nkshs)
    where
      (ct, cs) = encryptAndIncrement shsCipher (AssocData (cipherHashToBytes shsh)) (Plaintext pt)
      kshs     = mixHash shs { shsCipher = cs } (cipherTextToBytes ct)
      nkshs    = mixHash shs pt

decryptAndHash :: SymmetricHandshakeState c -> ScrubbedBytes -> undefined
decryptAndHash shs d = undefined

split :: SymmetricHandshakeState c -> (CipherState c, CipherState c)
split shs = undefined
