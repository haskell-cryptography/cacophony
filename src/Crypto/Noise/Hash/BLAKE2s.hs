{-# LANGUAGE TypeFamilies #-}
-------------------------------------------------
-- |
-- Module      : Crypto.Noise.Hash.BLAKE2s
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Hash.BLAKE2s
  ( -- * Types
    BLAKE2s
  ) where

import qualified Crypto.Hash     as H
import qualified Crypto.MAC.HMAC as M
import Data.ByteArray (ScrubbedBytes, convert, empty, snoc)
import Data.List      (unfoldr)
import Data.Word      (Word8)

import Crypto.Noise.Hash

-- | Represents the BLAKE2s hash.
data BLAKE2s

instance Hash BLAKE2s where
  newtype ChainingKey BLAKE2s = HCKB2s ScrubbedBytes
  newtype Digest      BLAKE2s = HDB2s  (H.Digest H.Blake2s_256)

  hashName   _  = "BLAKE2s"
  hashLength _  = 32
  hash          = hash'
  hashHKDF      = hkdf
  hashBytesToCK = bytesToCK
  hashCKToBytes = ckToBytes
  hashToBytes   = toBytes

hash' :: ScrubbedBytes
      -> Digest BLAKE2s
hash' bs = HDB2s $ H.hash bs

hkdf :: ChainingKey BLAKE2s
     -> ScrubbedBytes
     -> Word8
     -> [ScrubbedBytes]
hkdf (HCKB2s ck) keyMat numOutputs = loop (empty, 1)
  where
    hmac key info = convert (M.hmac key info :: M.HMAC H.Blake2s_256) :: ScrubbedBytes
    tempKey = hmac ck keyMat
    loop = unfoldr $ \(c, i) -> let r = hmac tempKey (c `snoc` i) in
      if i == 0
        then Nothing
        else if i <= numOutputs
          then Just (r, (r, i + 1))
          else Nothing

bytesToCK :: ScrubbedBytes
          -> ChainingKey BLAKE2s
bytesToCK = HCKB2s

ckToBytes :: ChainingKey BLAKE2s
          -> ScrubbedBytes
ckToBytes (HCKB2s ck) = ck

toBytes :: Digest BLAKE2s
        -> ScrubbedBytes
toBytes (HDB2s d) = convert d
