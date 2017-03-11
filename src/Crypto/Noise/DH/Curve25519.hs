{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.DH.Curve25519
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.DH.Curve25519
  ( -- * Types
    Curve25519
  ) where

import Crypto.Error          (throwCryptoError, maybeCryptoError)
import Crypto.Random.Entropy (getEntropy)
import qualified Crypto.PubKey.Curve25519 as C
import Crypto.Noise.DH
import Data.ByteArray        (ScrubbedBytes, convert)

-- | Represents curve25519.
data Curve25519

instance DH Curve25519 where
  newtype PublicKey Curve25519 = PK25519 C.PublicKey
  newtype SecretKey Curve25519 = SK25519 C.SecretKey

  dhName   _    = "25519"
  dhLength _    = 32
  dhGenKey      = genKey
  dhPerform     = dh
  dhPubToBytes  = pubToBytes
  dhBytesToPub  = bytesToPub
  dhSecToBytes  = secToBytes
  dhBytesToPair = bytesToPair
  dhPubEq       = pubEq

genKey :: IO (KeyPair Curve25519)
genKey = do
  r <- getEntropy 32 :: IO ScrubbedBytes
  let sk = throwCryptoError . C.secretKey $ r
      pk = C.toPublic sk
  return (SK25519 sk, PK25519 pk)

dh :: SecretKey Curve25519 -> PublicKey Curve25519 -> ScrubbedBytes
dh (SK25519 sk) (PK25519 pk) = convert $ C.dh pk sk

pubToBytes :: PublicKey Curve25519 -> ScrubbedBytes
pubToBytes (PK25519 pk) = convert pk

bytesToPub :: ScrubbedBytes -> Maybe (PublicKey Curve25519)
bytesToPub = fmap PK25519 . maybeCryptoError . C.publicKey

secToBytes :: SecretKey Curve25519 -> ScrubbedBytes
secToBytes (SK25519 sk) = convert sk

bytesToPair :: ScrubbedBytes -> Maybe (KeyPair Curve25519)
bytesToPair bs = do
  sk <- maybeCryptoError . C.secretKey $ bs
  return (SK25519 sk, PK25519 (C.toPublic sk))

pubEq :: PublicKey Curve25519
      -> PublicKey Curve25519
      -> Bool
pubEq (PK25519 a) (PK25519 b) = a == b
