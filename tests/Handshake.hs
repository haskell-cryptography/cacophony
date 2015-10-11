{-# LANGUAGE OverloadedStrings #-}
module Handshake where

import Imports
import Instances()

import Crypto.Noise.Handshake
import Crypto.Noise.Types
import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve.Curve25519

import Data.ByteString (ByteString)

emptyPT :: Plaintext
emptyPT = Plaintext $ convert ("" :: ByteString)

--------------------------------------------------------------------------------
-- Noise_NN

hsnNN :: ScrubbedBytes
hsnNN = convert ("Noise_NN_25519_ChaChaPoly" :: ByteString)

aliceNN, bobNN :: HandshakeState ChaChaPoly1305 Curve25519
aliceNN = handshakeState hsnNN Nothing Nothing Nothing Nothing Nothing
bobNN = handshakeState hsnNN Nothing Nothing Nothing Nothing Nothing

doNN :: Plaintext -> Property
doNN pt = ioProperty $ do
  (aliceToBob1, aliceNN') <- writeHandshakeMsg aliceNN noiseNNI1 emptyPT
  let (_, bobNN') = readHandshakeMsg bobNN aliceToBob1 noiseNNR1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobNN' noiseNNR2 emptyPT
  let (_, csAlice1, csAlice2) = readHandshakeMsgFinal aliceNN' bobToAlice1 noiseNNI2

  return $ conjoin
    [ (decrypt csBob1 . encrypt csAlice1) pt === pt
    , (decrypt csBob2 . encrypt csAlice2) pt === pt
    , (decrypt csAlice1 . encrypt csBob1) pt === pt
    , (decrypt csAlice2 . encrypt csBob2) pt === pt
    ]

  where
    encrypt cs p = fst $ encryptPayload p cs
    decrypt cs ct = fst $ decryptPayload ct cs

tests :: TestTree
tests = testGroup "Handshakes"
  [ testProperty "Noise_NN" $ property doNN
  ]
