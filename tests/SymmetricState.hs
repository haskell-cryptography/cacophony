{-# LANGUAGE OverloadedStrings #-}
module SymmetricState where

import Imports
import Instances()

import Control.Monad.State (runState, state)

import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Internal.SymmetricState
import Crypto.Noise.Types
import Data.ByteArray.Extend

shs :: SymmetricState ChaChaPoly1305 SHA256
shs = symmetricState $ bsToSB' "handshake name"

roundTripProp :: Plaintext -> Property
roundTripProp pt = (decrypt . encrypt) pt === pt
  where
    encrypt p = encryptAndHash p shs
    decrypt (ct, _) = fst $ decryptAndHash (cipherBytesToText ct) shs

manyRoundTripsProp :: [Plaintext] -> Property
manyRoundTripsProp pts = (fst . manyDecrypts . manyEncrypts) pts === pts
  where
    encrypt = encryptAndHash
    decrypt = decryptAndHash . cipherBytesToText
    doMany f = runState . mapM (state . f)
    manyEncrypts xs = doMany encrypt xs shs
    manyDecrypts (cts, _) = doMany decrypt cts shs

tests :: TestTree
tests = testGroup "SymmetricState"
  [ testProperty "ChaChaPoly1305 one roundtrip" $ property roundTripProp
  , testProperty "ChaChaPoly1305 many roundtrips" $ property manyRoundTripsProp
  ]
