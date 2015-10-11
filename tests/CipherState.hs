module CipherState where

import Imports
import Instances()

import Control.Monad.State (runState, state)

import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Internal.CipherState

roundTripProp :: AssocData -> Plaintext -> CipherState ChaChaPoly1305 -> Property
roundTripProp ad pt cs = (decrypt . encrypt) pt === pt
  where
    encrypt p = encryptAndIncrement ad p cs
    decrypt (ct, _) = fst $ decryptAndIncrement ad ct cs

manyRoundTripsProp :: AssocData -> [Plaintext] -> CipherState ChaChaPoly1305 -> Property
manyRoundTripsProp ad pts cs = (fst . manyDecrypts . manyEncrypts) pts === pts
  where
    encrypt = encryptAndIncrement ad
    decrypt = decryptAndIncrement ad
    doMany f xs = runState . mapM (state . f) $ xs
    manyEncrypts xs = doMany encrypt xs cs
    manyDecrypts (cts, _) = doMany decrypt cts cs

tests :: TestTree
tests = testGroup "CipherState"
  [ testProperty "ChaChaPoly1305 one roundtrip" $ property roundTripProp
  , testProperty "ChaChaPoly1305 many roundtrips" $ property manyRoundTripsProp
  ]
