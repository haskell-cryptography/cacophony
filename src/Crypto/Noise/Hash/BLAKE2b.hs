{-# LANGUAGE TypeFamilies #-}
-------------------------------------------------
-- |
-- Module      : Crypto.Noise.Hash.BLAKE2b
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Hash.BLAKE2b
  ( -- * Types
    BLAKE2b
  ) where

import qualified Crypto.Hash      as H
import qualified Crypto.MAC.HMAC  as M
import Data.ByteArray (ScrubbedBytes, convert, empty, snoc)
import Data.List      (unfoldr)
import Data.Word      (Word8)

import Crypto.Noise.Hash

-- | Represents the BLAKE2b hash.
data BLAKE2b

instance Hash BLAKE2b where
  newtype ChainingKey BLAKE2b = HCKB2b ScrubbedBytes
  newtype Digest      BLAKE2b = HDB2b  (H.Digest H.Blake2b_512)

  hashName   _  = "BLAKE2b"
  hashLength _  = 64
  hash          = hash'
  hashHKDF      = hkdf
  hashBytesToCK = bytesToCK
  hashCKToBytes = ckToBytes
  hashToBytes   = toBytes

hash' :: ScrubbedBytes
      -> Digest BLAKE2b
hash' bs = HDB2b $ H.hash bs

hkdf :: ChainingKey BLAKE2b
     -> ScrubbedBytes
     -> Word8
     -> [ScrubbedBytes]
hkdf (HCKB2b ck) keyMat numOutputs = loop (empty, 1)
  where
    hmac key info = convert (M.hmac key info :: M.HMAC H.Blake2b_512) :: ScrubbedBytes
    tempKey = hmac ck keyMat
    loop = unfoldr $ \(c, i) -> let r = hmac tempKey (c `snoc` i) in
      if i == 0
        then Nothing
        else if i <= numOutputs
          then Just (r, (r, i + 1))
          else Nothing

bytesToCK :: ScrubbedBytes
          -> ChainingKey BLAKE2b
bytesToCK = HCKB2b

ckToBytes :: ChainingKey BLAKE2b
          -> ScrubbedBytes
ckToBytes (HCKB2b ck) = ck

toBytes :: Digest BLAKE2b
        -> ScrubbedBytes
toBytes (HDB2b d) = convert d
