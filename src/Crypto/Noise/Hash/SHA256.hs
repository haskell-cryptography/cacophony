{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Hash.SHA256
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Hash.SHA256
  ( -- * Types
    SHA256
  ) where

import qualified Crypto.Hash     as H
import qualified Crypto.MAC.HMAC as M
import Data.ByteArray (ScrubbedBytes, convert)

import Crypto.Noise.Hash

-- | Represents the SHA256 hash.
data SHA256

instance Hash SHA256 where
  newtype ChainingKey SHA256 = HCKSHA256 ScrubbedBytes
  newtype Digest      SHA256 = HDSHA256  (H.Digest H.SHA256)

  hashName   _  = "SHA256"
  hashLength _  = 32
  hash          = hash'
  hashHKDF      = hkdf
  hashBytesToCK = bytesToCK
  hashCKToBytes = ckToBytes
  hashToBytes   = toBytes

hash' :: ScrubbedBytes -> Digest SHA256
hash' bs = HDSHA256 $ H.hash bs

hkdf :: ChainingKey SHA256 -> ScrubbedBytes -> (ChainingKey SHA256, ScrubbedBytes)
hkdf (HCKSHA256 ck) d = (HCKSHA256 ck', sk)
  where
    x01, x02 :: ScrubbedBytes
    x01   = "\x01"
    x02   = "\x02"

    hmac1 = M.hmac ck d :: M.HMAC H.SHA256
    temp  = convert hmac1 :: ScrubbedBytes
    hmac2 = M.hmac temp x01 :: M.HMAC H.SHA256
    hmac3 = M.hmac temp (convert hmac2 `mappend` x02) :: M.HMAC H.SHA256
    ck'   = convert hmac2
    sk    = convert hmac3

bytesToCK :: ScrubbedBytes -> ChainingKey SHA256
bytesToCK = HCKSHA256

ckToBytes :: ChainingKey SHA256 -> ScrubbedBytes
ckToBytes (HCKSHA256 ck) = ck

toBytes :: Digest SHA256 -> ScrubbedBytes
toBytes (HDSHA256 d) = convert d
