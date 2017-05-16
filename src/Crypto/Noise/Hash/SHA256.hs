{-# LANGUAGE TypeFamilies #-}
-------------------------------------------------
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
import Data.ByteArray (ScrubbedBytes, convert, empty, snoc)
import Data.List      (unfoldr)
import Data.Word      (Word8)

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

hkdf :: ChainingKey SHA256
     -> ScrubbedBytes
     -> Word8
     -> [ScrubbedBytes]
hkdf (HCKSHA256 ck) keyMat numOutputs = loop (empty, 1)
  where
    hmac key info = convert (M.hmac key info :: M.HMAC H.SHA256) :: ScrubbedBytes
    tempKey = hmac ck keyMat
    loop = unfoldr $ \(c, i) -> let r = hmac tempKey (c `snoc` i) in
      if i == 0
        then Nothing
        else if i <= numOutputs
          then Just (r, (r, i + 1))
          else Nothing

bytesToCK :: ScrubbedBytes -> ChainingKey SHA256
bytesToCK = HCKSHA256

ckToBytes :: ChainingKey SHA256 -> ScrubbedBytes
ckToBytes (HCKSHA256 ck) = ck

toBytes :: Digest SHA256 -> ScrubbedBytes
toBytes (HDSHA256 d) = convert d
