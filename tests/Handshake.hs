{-# LANGUAGE OverloadedStrings #-}
module Handshake where

import Imports

import Crypto.Noise.Handshake
import Crypto.Noise.Internal.CipherState (csk)
import Crypto.Noise.Types
import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve.Curve25519

import Data.ByteString (ByteString)

--------------------------------------------------------------------------------
-- Noise_NN

hsnNN :: ScrubbedBytes
hsnNN = convert ("Noise_NN_25519_ChaChaPoly" :: ByteString)

aliceNN, bobNN :: HandshakeState ChaChaPoly1305 Curve25519
aliceNN = handshakeState hsnNN Nothing Nothing Nothing Nothing Nothing
bobNN = handshakeState hsnNN Nothing Nothing Nothing Nothing Nothing

doNN :: IO Bool
doNN = do
  (aliceToBob1, aliceNN') <- writeHandshakeMsg aliceNN noiseNNI1 $ Plaintext $ convert ("" :: ByteString)
  let (_, bobNN') = readHandshakeMsg bobNN aliceToBob1 noiseNNR1
  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobNN' noiseNNR2 $ Plaintext $ convert ("" :: ByteString)
  let (_, csAlice1, csAlice2) = readHandshakeMsgFinal aliceNN' bobToAlice1 noiseNNI2
  return $ csk csAlice1 == csk csBob1 && csk csAlice2 == csk csBob2

tests :: TestTree
tests = testGroup "Handshakes"
  [ testProperty "Noise_NN" $ ioProperty doNN
  ]
