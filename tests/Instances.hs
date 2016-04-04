{-# LANGUAGE FlexibleInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Instances where

import Control.Monad   (liftM, replicateM)
import Data.ByteString (pack)
import Test.QuickCheck

import Crypto.Noise.Cipher
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Types
import Data.ByteArray.Extend

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
