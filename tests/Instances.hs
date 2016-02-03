{-# LANGUAGE FlexibleInstances, StandaloneDeriving #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Instances where

import Control.Monad   (liftM, replicateM)
import Data.ByteString (pack)
import Test.QuickCheck

import Crypto.Noise.Cipher
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Types (ScrubbedBytes, Plaintext(..), bsToSB',
                           sbEq, sbToBS')

instance Eq Plaintext where
  (Plaintext pt1) == (Plaintext pt2) = pt1 `sbEq` pt2

instance Show Plaintext where
  show (Plaintext pt) = show . sbToBS' $ pt

instance Show AssocData where
  show (AssocData ad) = show . sbToBS' $ ad

instance Show (SymmetricKey a) where
  show _ = "<symmetric key>"

instance Show (Nonce a) where
  show _ = "<nonce>"

deriving instance Show (CipherState a)

instance Arbitrary ScrubbedBytes where
  arbitrary = bsToSB' `liftM` pack <$> arbitrary

instance Arbitrary Plaintext where
  arbitrary = Plaintext `liftM` arbitrary

instance Arbitrary AssocData where
  arbitrary = AssocData `liftM` arbitrary

instance Cipher c => Arbitrary (CipherState c) where
  arbitrary = do
    a <- (bsToSB' . pack) <$> replicateM 32 arbitrary
    return $ CipherState (cipherBytesToSym a) cipherZeroNonce
