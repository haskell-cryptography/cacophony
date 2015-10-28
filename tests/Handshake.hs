{-# LANGUAGE OverloadedStrings #-}
module Handshake where

import Imports
import Instances()

import Data.Proxy

import Crypto.Noise.Handshake
import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Hash
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Types

import Data.ByteString (ByteString)
import qualified Data.ByteArray as BA (concat)

sampleHSPT :: Plaintext
sampleHSPT = Plaintext $ convert ("cacophony" :: ByteString)

makeHSN :: ByteString -> ScrubbedBytes
makeHSN hs = BA.concat [convert hs, u, a, u, b, u, c]
  where
    a = curveName  (Proxy :: Proxy Curve25519)
    b = cipherName (Proxy :: Proxy ChaChaPoly1305)
    c = hashName   (Proxy :: Proxy SHA256)
    u = convert    ("_" :: ByteString)

--------------------------------------------------------------------------------
-- Noise_NN

hsnNN :: ScrubbedBytes
hsnNN = makeHSN "Noise_NN"

aliceNN, bobNN :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
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
hsnSN = makeHSN "Noise_SN"

doSN :: Plaintext -> Property
doSN pt = ioProperty $ do
  aliceStaticKey@(_, aliceStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceSN = handshakeState
                hsnSN
                (Just aliceStaticKey)
                Nothing
                Nothing
                Nothing
                (Just noiseSNI0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobSN = handshakeState
              hsnSN
              Nothing
              Nothing
              (Just aliceStaticPK)
              Nothing
              (Just noiseSNR0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

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
