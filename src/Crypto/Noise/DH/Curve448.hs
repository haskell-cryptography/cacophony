{-# LANGUAGE TypeFamilies #-}
-------------------------------------------------
-- |
-- Module      : Crypto.Noise.DH.Curve448
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.DH.Curve448
  ( -- * Types
    Curve448
  ) where

import Crypto.Error          (throwCryptoError, maybeCryptoError)
import Crypto.Random.Entropy (getEntropy)
import qualified Crypto.PubKey.Ed448 as C
import Crypto.Noise.DH
import Data.ByteArray        (ScrubbedBytes, convert)

-- | Represents curve448.
data Curve448

instance DH Curve448 where
  newtype PublicKey Curve448 = PK448 C.PublicKey
  newtype SecretKey Curve448 = SK448 C.SecretKey

  dhName   _    = "448"
  dhLength _    = 56
  dhGenKey      = genKey
  dhPerform     = dh
  dhPubToBytes  = pubToBytes
  dhBytesToPub  = bytesToPub
  dhSecToBytes  = secToBytes
  dhBytesToPair = bytesToPair
  dhPubEq       = pubEq

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

bytesToPub :: ScrubbedBytes -> Maybe (PublicKey Curve448)
bytesToPub = fmap PK448 . maybeCryptoError . C.publicKey

secToBytes :: SecretKey Curve448 -> ScrubbedBytes
secToBytes (SK448 sk) = convert sk

bytesToPair :: ScrubbedBytes -> Maybe (KeyPair Curve448)
bytesToPair bs = do
  sk <- maybeCryptoError . C.secretKey $ bs
  return (SK448 sk, PK448 (C.toPublic sk))

pubEq :: PublicKey Curve448
      -> PublicKey Curve448
      -> Bool
pubEq (PK448 a) (PK448 b) = a == b
