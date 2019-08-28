{-# LANGUAGE TypeFamilies #-}
-------------------------------------------------
-- |
-- Module      : Crypto.Noise.DH.Secp256k1
-- Maintainer  : Janus Troelsen <ysangkok@gmail.com>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.DH.Secp256k1
  ( -- * Types
    Secp256k1
  ) where

import Data.ByteArray (ScrubbedBytes)

import Crypto.Random.Entropy (getEntropy)
--import Crypto.PubKey.ECC.P256K1 (Point, Scalar, pointToBinary, pointDh, scalarFromInteger, pointFromBinary, scalarToBinary, scalarToPoint)
import Crypto.Noise.DH
import Crypto.Secp256k1
import Data.ByteArray (convert)

-- | Represents secp256k1.
data Secp256k1

instance DH Secp256k1 where
  newtype PublicKey Secp256k1 = PKS256k1 PubKey
  newtype SecretKey Secp256k1 = SKS256k1 SecKey

  dhName   _    = "secp256k1"
  dhLength _    = 33
  dhGenKey      = genKey
  dhPerform     = dh
  dhPubToBytes  = pubToBytes
  dhBytesToPub  = bytesToPub
  dhSecToBytes  = secToBytes
  dhBytesToPair = bytesToPair
  dhPubEq       = pubEq

genKey :: IO (KeyPair Secp256k1)
genKey = do
  r <- getEntropy 32 :: IO ScrubbedBytes
  case bytesToPair r of
    Just x -> return x
    Nothing -> genKey

dh :: SecretKey Secp256k1 -> PublicKey Secp256k1 -> ScrubbedBytes
dh (SKS256k1 sk) (PKS256k1 pk) = convert $ ecdh pk sk

pubToBytes :: PublicKey Secp256k1 -> ScrubbedBytes
pubToBytes (PKS256k1 pk) = convert $ exportPubKey True pk

bytesToPub :: ScrubbedBytes -> Maybe (PublicKey Secp256k1)
bytesToPub bytes = fmap PKS256k1 $ importPubKey $ convert bytes

secToBytes :: SecretKey Secp256k1 -> ScrubbedBytes
secToBytes (SKS256k1 sk) = convert $ getSecKey sk

bytesToPair :: ScrubbedBytes -> Maybe (KeyPair Secp256k1)
bytesToPair bs = do
  sk <- secKey $ convert bs
  pk <- pure $ derivePubKey sk
  return (SKS256k1 sk, PKS256k1 pk)

pubEq :: PublicKey Secp256k1
      -> PublicKey Secp256k1
      -> Bool
pubEq (PKS256k1 a) (PKS256k1 b) = a == b
