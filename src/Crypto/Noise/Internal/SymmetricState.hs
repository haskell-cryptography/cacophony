{-# LANGUAGE TemplateHaskell, ScopedTypeVariables, TypeApplications #-}
-----------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.SymmetricState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Internal.SymmetricState where

import Control.Exception.Safe
import Control.Lens
import Data.ByteArray  (ScrubbedBytes, length, replicate, convert, ByteArray)
import Data.Proxy
import Prelude hiding  (length, replicate)
import Debug.Trace
import Data.ByteString (ByteString)
import Data.ByteString.Base16
import Data.Maybe (fromMaybe)
import Crypto.Noise.Hash.SHA256

import Crypto.Noise.Cipher
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState

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
    ck         = trace ("ck init: " ++ (show $ encode $ convert $ sshBytes h)) (hashBytesToCK . sshBytes $ h)
    cs         = cipherState Nothing

-- | Mixes keying material in to the SymmetricState.
mixKey :: (Cipher c, Hash h)
       => ScrubbedBytes
       -> SymmetricState c h
       -> SymmetricState c h
mixKey keyMat ss =
    -- convert $ BS.concat [conv3 q, convert $ DH.getShared curve d q]
    -- encode $ convert $ hashCKToBytes $ ss ^. ssck CORRECT
    traceStack ("mixKey hash now: " ++ (show $ keyMat == (convert $ fst $ decode $ "1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3")) ++ " " ++ (show [encode $ convert $ keyMat, encode $ convert $ k])) res
  where
    --[t1, t2] = hashHKDF @SHA256 (hashBytesToCK $ convert $ fst $ decode $ "2640f52eebcd9e882958951c794250eedb28002c05d7dc2ea0f195406042caf1") (convert $ fst $ decode $ "1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3") 2
    [ck, k] = hashHKDF (ss ^. ssck) keyMat 2
    -- k is truncated automatically by cipherBytesToSym
    cs      = cipherState . Just . cipherBytesToSym $ k
    res = ss & ssCipher .~ cs
             & ssck     .~ hashBytesToCK ck

-- | Mixes arbitrary data in to the SymmetricState.
mixHash :: Hash h
        => ScrubbedBytes
        -> SymmetricState c h
        -> SymmetricState c h
mixHash d ss = let
    res = ss & ssh %~ Right . hash . (`mappend` d) . sshBytes
  in
    trace ("mixHash d: " ++ (show $ encode $ convert d)) res

-- | Mixes key material and arbitrary data in to the SymmetricState.
--   Note that this is not isomorphic to @mixHash . mixKey@.
mixKeyAndHash :: (Cipher c, Hash h)
              => ScrubbedBytes
              -> SymmetricState c h
              -> SymmetricState c h
mixKeyAndHash keyMat ss = trace ("mixKeyAndHash: " ++ (show [ck, h, k])) res
  where
    [ck, h, k] = hashHKDF (ss ^. ssck) keyMat 3
    ss'        = mixHash h ss
    cs         = cipherState . Just . cipherBytesToSym $ k
    res        = ss' & ssCipher .~ cs
                     & ssck     .~ hashBytesToCK ck

-- | Encrypts the given Plaintext. Note that this may not actually perform
--   encryption if a key has not been established yet, in which case the
--   original plaintext is returned.
encryptAndHash :: (MonadThrow m, Cipher c, Hash h)
               => Plaintext
               -> SymmetricState c h
               -> m (Ciphertext c, SymmetricState c h)
encryptAndHash pt ss = do
  --let ss = set (ssCipher . csk) (Just $ cipherBytesToSym $ convert $ fst $ decode $ "e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f") initss
  (ct, cs) <- encryptWithAd (sshBytes (ss ^. ssh)) pt (ss ^. ssCipher)
  let ss' = mixHash (cipherTextToBytes ct) ss
  let res = (ct, ss' & ssCipher .~ cs)
  -- CORRECT:
  --        encode $ convert $ nonceToBytes $ ss ^. ssCipher ^. csn
  --        encode $ convert $ sshBytes $ _ssh ss
  --        encode $ convert $ pt
  return $ trace ("encryptAndHash: " ++ (show [show $ fmap (encode . convert . cipherSymToBytes) $ ss ^. ssCipher ^. csk, show $ encode $ convert $ cipherTextToBytes ct])) res

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
split ss = trace ("split: " ++ (show [k1, k2])) (c1, c2)
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
