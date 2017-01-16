{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
----------------------------------------------------------------
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
import Data.ByteArray (ScrubbedBytes, convert)

import Crypto.Noise.Hash

-- | Represents the BLAKE2s hash.
data BLAKE2s

instance Hash BLAKE2s where
  newtype ChainingKey BLAKE2s = HCKB2s ScrubbedBytes
  newtype Digest      BLAKE2s = HDB2s  (H.Digest H.Blake2s_256)

  hashName   _  = "BLAKE2s"
  hashLength _  = 32
  hash          = hashS
  hashHKDF      = hkdfS
  hashBytesToCK = bytesToCKS
  hashCKToBytes = ckToBytesS
  hashToBytes   = toBytesS

hashS :: ScrubbedBytes
       -> Digest BLAKE2s
hashS bs = HDB2s $ H.hash bs

hkdfS :: ChainingKey BLAKE2s
       -> ScrubbedBytes
       -> (ChainingKey BLAKE2s, ScrubbedBytes)
hkdfS (HCKB2s ck) d = (HCKB2s ck', sk)
  where
    x01, x02 :: ScrubbedBytes
    x01   = "\x01"
    x02   = "\x02"

    hmac1 = M.hmac ck d :: M.HMAC H.Blake2s_256
    temp  = convert hmac1 :: ScrubbedBytes
    hmac2 = M.hmac temp x01 :: M.HMAC H.Blake2s_256
    hmac3 = M.hmac temp (convert hmac2 `mappend` x02) :: M.HMAC H.Blake2s_256
    ck'   = convert hmac2
    sk    = convert hmac3

bytesToCKS :: ScrubbedBytes
            -> ChainingKey BLAKE2s
bytesToCKS = HCKB2s

ckToBytesS :: ChainingKey BLAKE2s
            -> ScrubbedBytes
ckToBytesS (HCKB2s ck) = ck

toBytesS :: Digest BLAKE2s
          -> ScrubbedBytes
toBytesS (HDB2s d) = convert d
