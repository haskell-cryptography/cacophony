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
import Data.ByteArray (ScrubbedBytes, convert)

import Crypto.Noise.Hash

-- | Represents the BLAKE2b hash.
data BLAKE2b

instance Hash BLAKE2b where
  newtype ChainingKey BLAKE2b = HCKB2s ScrubbedBytes
  newtype Digest      BLAKE2b = HDB2s  (H.Digest H.Blake2b_512)

  hashName   _  = "BLAKE2b"
  hashLength _  = 64
  hash          = hashB
  hashHKDF      = hkdfB
  hashBytesToCK = bytesToCKB
  hashCKToBytes = ckToBytesB
  hashToBytes   = toBytesB

hashB :: ScrubbedBytes
       -> Digest BLAKE2b
hashB bs = HDB2s $ H.hash bs

hkdfB :: ChainingKey BLAKE2b
       -> ScrubbedBytes
       -> (ChainingKey BLAKE2b, ScrubbedBytes)
hkdfB (HCKB2s ck) d = (HCKB2s ck', sk)
  where
    x01, x02 :: ScrubbedBytes
    x01   = "\x01"
    x02   = "\x02"

    hmac1 = M.hmac ck d :: M.HMAC H.Blake2b_512
    temp  = convert hmac1 :: ScrubbedBytes
    hmac2 = M.hmac temp x01 :: M.HMAC H.Blake2b_512
    hmac3 = M.hmac temp (convert hmac2 `mappend` x02) :: M.HMAC H.Blake2b_512
    ck'   = convert hmac2
    sk    = convert hmac3

bytesToCKB :: ScrubbedBytes
            -> ChainingKey BLAKE2b
bytesToCKB = HCKB2s

ckToBytesB :: ChainingKey BLAKE2b
            -> ScrubbedBytes
ckToBytesB (HCKB2s ck) = ck

toBytesB :: Digest BLAKE2b
          -> ScrubbedBytes
toBytesB (HDB2s d) = convert d
