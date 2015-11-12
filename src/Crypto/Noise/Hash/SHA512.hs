{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleInstances #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Hash.SHA512
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Hash.SHA512
  ( -- * Types
    SHA512
  ) where

import qualified Crypto.Hash     as H
import qualified Crypto.MAC.HMAC as M

import Crypto.Noise.Hash
import Crypto.Noise.Types

-- | Represents the SHA512 hash.
data SHA512

instance Hash SHA512 where
  newtype ChainingKey SHA512 = HCKSHA512 ScrubbedBytes
  newtype Digest      SHA512 = HDSHA512  (H.Digest H.SHA512)

  hashName   _  = bsToSB' "SHA512"
  hashLength _  = 64
  hash          = hash'
  hashHKDF      = hkdf
  hashBytesToCK = bytesToCK
  hashCKToBytes = ckToBytes
  hashToBytes   = toBytes

hash' :: ScrubbedBytes -> Digest SHA512
hash' bs = HDSHA512 $ H.hash bs

hkdf :: ChainingKey SHA512 -> ScrubbedBytes -> (ChainingKey SHA512, ScrubbedBytes)
hkdf (HCKSHA512 ck) d = (HCKSHA512 ck', sk)
  where
    x01   = bsToSB' "\x01"
    x02   = bsToSB' "\x02"

    hmac1 = M.hmac ck d :: M.HMAC H.SHA512
    temp  = convert . M.hmacGetDigest $ hmac1 :: ScrubbedBytes
    hmac2 = M.hmac temp x01 :: M.HMAC H.SHA512
    hmac3 = M.hmac temp (convert hmac2 `append` x02) :: M.HMAC H.SHA512
    ck'   = convert . M.hmacGetDigest $ hmac2
    sk    = convert . M.hmacGetDigest $ hmac3

bytesToCK :: ScrubbedBytes -> ChainingKey SHA512
bytesToCK = HCKSHA512

ckToBytes :: ChainingKey SHA512 -> ScrubbedBytes
ckToBytes (HCKSHA512 ck) = ck

toBytes :: Digest SHA512 -> ScrubbedBytes
toBytes (HDSHA512 d) = convert d
