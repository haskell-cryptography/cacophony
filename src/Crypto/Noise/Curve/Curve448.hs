{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleInstances #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Curve.Curve448
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Curve.Curve448
  ( -- * Types
    Curve448
  ) where

import Crypto.Error          (throwCryptoError)
import Crypto.Random.Entropy (getEntropy)
import qualified Crypto.PubKey.Ed448 as C
import Crypto.Noise.Curve
import Crypto.Noise.Types

-- | Represents curve448.
data Curve448

instance Curve Curve448 where
  newtype PublicKey Curve448 = PK448 C.PublicKey
  newtype SecretKey Curve448 = SK448 C.SecretKey

  curveName   _    = bsToSB' "448"
  curveLength _    = 56
  curveGenKey      = genKey
  curveDH          = dh
  curvePubToBytes  = pubToBytes
  curveBytesToPub  = bytesToPub
  curveSecToBytes  = secToBytes
  curveBytesToPair = bytesToPair

genKey :: IO (KeyPair Curve448)
genKey = do
  r <- getEntropy 56 :: IO ScrubbedBytes
  let sk = throwCryptoError . C.secretKey $ r
      pk = C.toPublic sk
  return (SK448 sk, PK448 pk)

dh :: SecretKey Curve448 -> PublicKey Curve448 -> ScrubbedBytes
dh (SK448 sk) (PK448 pk) = convert $ C.dh pk sk

pubToBytes :: PublicKey Curve448 -> ScrubbedBytes
pubToBytes (PK448 pk) = convert pk

bytesToPub :: ScrubbedBytes -> PublicKey Curve448
bytesToPub = PK448 . throwCryptoError . C.publicKey

secToBytes :: SecretKey Curve448 -> ScrubbedBytes
secToBytes (SK448 sk) = convert sk

bytesToPair :: ScrubbedBytes -> KeyPair Curve448
bytesToPair bs = (SK448 sk, PK448 pk)
  where
    sk = throwCryptoError . C.secretKey $ bs
    pk = C.toPublic sk
