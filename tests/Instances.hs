{-# LANGUAGE FlexibleInstances, StandaloneDeriving #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Instances where

import Control.Monad (liftM, replicateM)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import Test.QuickCheck

import Crypto.Noise.Cipher
import Crypto.Noise.Internal.CipherState

instance Eq Plaintext where
  (Plaintext pt1) == (Plaintext pt2) = pt1 `BA.eq` pt2

instance Show Plaintext where
  show (Plaintext pt) = show (BA.convert pt :: BS.ByteString)

instance Show AssocData where
  show (AssocData ad) = show (BA.convert ad :: BS.ByteString)

instance Show (SymmetricKey a) where
  show _ = "<symmetric key>"

instance Show (Nonce a) where
  show _ = "<nonce>"

deriving instance Show (CipherState a)

instance Arbitrary BA.ScrubbedBytes where
  arbitrary = BA.convert `liftM` BS.pack <$> arbitrary

instance Arbitrary Plaintext where
  arbitrary = Plaintext `liftM` arbitrary

instance Arbitrary AssocData where
  arbitrary = AssocData `liftM` arbitrary

instance Cipher c => Arbitrary (CipherState c) where
  arbitrary = do
    a <- (BA.convert . BS.pack) <$> replicateM 32 arbitrary
    return $ CipherState (cipherBytesToSym a) cipherZeroNonce
