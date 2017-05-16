{-# LANGUAGE TypeFamilies #-}
-------------------------------------------------
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
import Data.ByteArray (ScrubbedBytes, convert, empty, snoc)
import Data.List      (unfoldr)
import Data.Word      (Word8)

import Crypto.Noise.Hash

-- | Represents the SHA512 hash.
data SHA512

instance Hash SHA512 where
  newtype ChainingKey SHA512 = HCKSHA512 ScrubbedBytes
  newtype Digest      SHA512 = HDSHA512  (H.Digest H.SHA512)

  hashName   _  = "SHA512"
  hashLength _  = 64
  hash          = hash'
  hashHKDF      = hkdf
  hashBytesToCK = bytesToCK
  hashCKToBytes = ckToBytes
  hashToBytes   = toBytes

hash' :: ScrubbedBytes -> Digest SHA512
hash' bs = HDSHA512 $ H.hash bs

hkdf :: ChainingKey SHA512
     -> ScrubbedBytes
     -> Word8
     -> [ScrubbedBytes]
hkdf (HCKSHA512 ck) keyMat numOutputs = loop (empty, 1)
  where
    hmac key info = convert (M.hmac key info :: M.HMAC H.SHA512) :: ScrubbedBytes
    tempKey = hmac ck keyMat
    loop = unfoldr $ \(c, i) -> let r = hmac tempKey (c `snoc` i) in
      if i == 0
        then Nothing
        else if i <= numOutputs
          then Just (r, (r, i + 1))
          else Nothing

bytesToCK :: ScrubbedBytes -> ChainingKey SHA512
bytesToCK = HCKSHA512

ckToBytes :: ChainingKey SHA512 -> ScrubbedBytes
ckToBytes (HCKSHA512 ck) = ck

toBytes :: Digest SHA512 -> ScrubbedBytes
toBytes (HDSHA512 d) = convert d
