{-# LANGUAGE OverloadedStrings #-}
module Handshake where

import Imports
import Instances()

import Crypto.Noise.Handshake
import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Types

import Data.ByteString (ByteString)

sampleHSPT :: Plaintext
sampleHSPT = Plaintext $ convert ("cacophony" :: ByteString)

--------------------------------------------------------------------------------
-- Noise_NN

hsnNN :: ScrubbedBytes
hsnNN = convert ("Noise_NN_25519_ChaChaPoly" :: ByteString)

aliceNN, bobNN :: HandshakeState ChaChaPoly1305 Curve25519
aliceNN = handshakeState hsnNN Nothing Nothing Nothing Nothing Nothing
bobNN = handshakeState hsnNN Nothing Nothing Nothing Nothing Nothing

doNN :: Plaintext -> Property
doNN pt = ioProperty $ do
  (aliceToBob1, aliceNN') <- writeHandshakeMsg aliceNN noiseNNI1 sampleHSPT
  let (hsptFromAlice1, bobNN') = readHandshakeMsg bobNN aliceToBob1 noiseNNR1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobNN' noiseNNR2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal aliceNN' bobToAlice1 noiseNNI2

  return $ conjoin
    [ (decrypt csBob1 . encrypt csAlice1) pt === pt
    , (decrypt csBob2 . encrypt csAlice2) pt === pt
    , (decrypt csAlice1 . encrypt csBob1) pt === pt
    , (decrypt csAlice2 . encrypt csBob2) pt === pt
    , hsptFromAlice1 === sampleHSPT
    , hsptFromBob1   === sampleHSPT
    ]

  where
    encrypt cs p = fst $ encryptPayload p cs
    decrypt cs ct = fst $ decryptPayload ct cs

--------------------------------------------------------------------------------
-- Noise_SN

hsnSN :: ScrubbedBytes
hsnSN = convert ("Noise_SN_25519_ChaChaPoly" :: ByteString)

doSN :: Plaintext -> Property
doSN pt = ioProperty $ do
  aliceStaticKey@(_, aliceStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceSN = handshakeState
                hsnSN
                (Just aliceStaticKey)
                Nothing
                Nothing
                Nothing
                (Just noiseSNI0) :: HandshakeState ChaChaPoly1305 Curve25519

      bobSN = handshakeState
              hsnSN
              Nothing
              Nothing
              (Just aliceStaticPK)
              Nothing
              (Just noiseSNR0) :: HandshakeState ChaChaPoly1305 Curve25519

  (aliceToBob1, aliceSN') <- writeHandshakeMsg aliceSN noiseSNI1 sampleHSPT
  let (hsptFromAlice1, bobSN') = readHandshakeMsg bobSN aliceToBob1 noiseSNR1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobSN' noiseSNR2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal aliceSN' bobToAlice1 noiseSNI2

  return $ conjoin
    [ (decrypt csBob1 . encrypt csAlice1) pt === pt
    , (decrypt csBob2 . encrypt csAlice2) pt === pt
    , (decrypt csAlice1 . encrypt csBob1) pt === pt
    , (decrypt csAlice2 . encrypt csBob2) pt === pt
    , hsptFromAlice1 === sampleHSPT
    , hsptFromBob1   === sampleHSPT
    ]

  where
    encrypt cs p = fst $ encryptPayload p cs
    decrypt cs ct = fst $ decryptPayload ct cs

tests :: TestTree
tests = testGroup "Handshakes"
  [ testProperty "Noise_NN" $ property doNN
  , testProperty "Noise_SN" $ property doSN
  ]
