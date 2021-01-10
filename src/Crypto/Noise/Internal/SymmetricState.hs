{-# LANGUAGE TemplateHaskell, ScopedTypeVariables #-}
-----------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.SymmetricState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Internal.SymmetricState where

import Control.Exception.Safe ( MonadThrow )
import Control.Lens ( (&), (^.), (%~), (.~), makeLenses )
import Data.ByteArray  (ScrubbedBytes, length, replicate)
import Data.Proxy ( Proxy(..) )
import Prelude hiding  (length, replicate)

import Crypto.Noise.Cipher
    ( Plaintext,
      Cipher(Ciphertext, cipherBytesToSym, cipherTextToBytes) )
import Crypto.Noise.Hash
    ( Hash(ChainingKey, Digest, hashToBytes, hashLength, hash,
           hashBytesToCK, hashHKDF) )
import Crypto.Noise.Internal.CipherState
    ( CipherState, cipherState, encryptWithAd, decryptWithAd )

data SymmetricState c h =
  SymmetricState { _ssCipher :: CipherState c
                 , _ssck     :: ChainingKey h
                 , _ssh      :: Either ScrubbedBytes (Digest h)
                 }

$(makeLenses ''SymmetricState)

-- | Creates a new SymmetricState from the given protocol name.
symmetricState :: forall c h. (Cipher c, Hash h)
               => ScrubbedBytes
               -> SymmetricState c h
symmetricState protoName = SymmetricState cs ck h
  where
    hashLen    = hashLength (Proxy :: Proxy h)
    shouldHash = length protoName > hashLen
    h         = if shouldHash
                   then Right $ hash protoName
                   else Left $ protoName `mappend` replicate (hashLen - length protoName) 0
    ck         = hashBytesToCK . sshBytes $ h
    cs         = cipherState Nothing

-- | Mixes keying material in to the SymmetricState.
mixKey :: (Cipher c, Hash h)
       => ScrubbedBytes
       -> SymmetricState c h
       -> SymmetricState c h
mixKey keyMat ss = ss & ssCipher .~ cs
                      & ssck     .~ hashBytesToCK ck
  where
    [ck, k] = hashHKDF (ss ^. ssck) keyMat 2
    -- k is truncated automatically by cipherBytesToSym
    cs      = cipherState . Just . cipherBytesToSym $ k

-- | Mixes arbitrary data in to the SymmetricState.
mixHash :: Hash h
        => ScrubbedBytes
        -> SymmetricState c h
        -> SymmetricState c h
mixHash d ss = ss & ssh %~ Right . hash . (`mappend` d) . sshBytes

-- | Mixes key material and arbitrary data in to the SymmetricState.
--   Note that this is not isomorphic to @mixHash . mixKey@.
mixKeyAndHash :: (Cipher c, Hash h)
              => ScrubbedBytes
              -> SymmetricState c h
              -> SymmetricState c h
mixKeyAndHash keyMat ss = ss' & ssCipher .~ cs
                              & ssck     .~ hashBytesToCK ck
  where
    [ck, h, k] = hashHKDF (ss ^. ssck) keyMat 3
    ss'        = mixHash h ss
    cs         = cipherState . Just . cipherBytesToSym $ k

-- | Encrypts the given Plaintext. Note that this may not actually perform
--   encryption if a key has not been established yet, in which case the
--   original plaintext is returned.
encryptAndHash :: (MonadThrow m, Cipher c, Hash h)
               => Plaintext
               -> SymmetricState c h
               -> m (Ciphertext c, SymmetricState c h)
encryptAndHash pt ss = do
  (ct, cs) <- encryptWithAd (sshBytes (ss ^. ssh)) pt (ss ^. ssCipher)
  let ss' = mixHash (cipherTextToBytes ct) ss
  return (ct, ss' & ssCipher .~ cs)

-- | Decrypts the given Ciphertext. Note that this may not actually perform
--   decryption if a key as not been established yet, in which case the
--   original ciphertext is returned.
decryptAndHash :: (MonadThrow m, Cipher c, Hash h)
               => Ciphertext c
               -> SymmetricState c h
               -> m (Plaintext, SymmetricState c h)
decryptAndHash ct ss = do
  (pt, cs) <- decryptWithAd (sshBytes (ss ^. ssh)) ct (ss ^. ssCipher)
  let ss' = mixHash (cipherTextToBytes ct) ss
  return (pt, ss' & ssCipher .~ cs)

-- | Returns a pair of CipherStates for encrypting transport messages. The
--   first CipherState is for encrypting messages from the Initiator to the
--   Responder, and the second is for encrypting messages from the Responder
--   to the Initiator.
split :: (Cipher c, Hash h)
      => SymmetricState c h
      -> (CipherState c, CipherState c)
split ss = (c1, c2)
  where
    [k1, k2] = hashHKDF (ss ^. ssck) mempty 2
    c1       = cipherState . Just . cipherBytesToSym $ k1
    c2       = cipherState . Just . cipherBytesToSym $ k2

-- | Utility function to convert the hash state to ScrubbedBytes.
sshBytes :: Hash h
         => Either ScrubbedBytes (Digest h)
         -> ScrubbedBytes
sshBytes (Left  h) = h
sshBytes (Right h) = hashToBytes h
