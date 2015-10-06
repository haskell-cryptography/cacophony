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

import Data.Byteable
import Data.ByteString hiding (split)

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Internal.CipherState

data SymmetricHandshakeState c =
  SymmetricHandshakeState { shsCipher :: CipherState c
                          , shsHasKey :: Bool
                          , shsh      :: Digest c
                          }

symmetricHandshake :: Cipher c => ByteString -> SymmetricHandshakeState c
symmetricHandshake hsn = SymmetricHandshakeState cs False h
  where
    h  = cipherHash hsn
    cs = CipherState (cipherHashToKey h) cipherZeroNonce

mixKey :: (Cipher c, Curve d) => SymmetricHandshakeState c -> DHOutput d -> SymmetricHandshakeState c
mixKey SymmetricHandshakeState{..} dho = SymmetricHandshakeState cs True shsh
  where
    gk   = cipherGetKey (csk shsCipher) (csn shsCipher)
    hmac = cipherHMAC gk (Plaintext (curveDHBytes dho))
    cs   = CipherState (cipherHashToKey hmac) cipherZeroNonce

mixHash :: Byteable b => SymmetricHandshakeState c -> b -> SymmetricHandshakeState c
mixHash shs = undefined

encryptAndHash :: SymmetricHandshakeState c -> ByteString -> ByteString
encryptAndHash shs pt = undefined

decryptAndHash :: SymmetricHandshakeState c -> ByteString -> ByteString
decryptAndHash shs d = undefined

split :: SymmetricHandshakeState c -> (CipherState c, CipherState c)
split shs = undefined
