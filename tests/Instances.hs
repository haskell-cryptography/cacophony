{-# LANGUAGE FlexibleInstances, StandaloneDeriving #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Instances where

import Control.Monad (liftM)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import Test.QuickCheck

import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Internal.CipherState

instance Eq Plaintext where
  (Plaintext pt1) == (Plaintext pt2) = pt1 `BA.eq` pt2

instance Show Plaintext where
  show (Plaintext pt) = show (BA.convert pt :: BS.ByteString)

instance Show AssocData where
  show (AssocData ad) = show (BA.convert ad :: BS.ByteString)

instance Show (SymmetricKey ChaChaPoly1305) where
  show _ = "<symmetric key>"

instance Show (Nonce ChaChaPoly1305) where
  show _ = "<nonce>"

deriving instance Show (CipherState ChaChaPoly1305)

instance Arbitrary BA.ScrubbedBytes where
  arbitrary = BA.convert `liftM` BS.pack <$> arbitrary

instance Arbitrary Plaintext where
  arbitrary = Plaintext `liftM` arbitrary

instance Arbitrary AssocData where
  arbitrary = AssocData `liftM` arbitrary

instance Arbitrary (CipherState ChaChaPoly1305) where
  arbitrary = do
    h <- arbitrary
    let k = cipherHashToKey . cipherHash $ h
        n = cipherZeroNonce
    return $ CipherState k n
