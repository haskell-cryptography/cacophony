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
-- Noise_KN

hsnKN :: ScrubbedBytes
hsnKN = makeHSN "Noise_KN"

doKN :: Plaintext -> Property
doKN pt = ioProperty $ do
  aliceStaticKey@(_, aliceStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceKN = handshakeState
                hsnKN
                (Just aliceStaticKey)
                Nothing
                Nothing
                Nothing
                (Just noiseKNI0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobKN = handshakeState
              hsnKN
              Nothing
              Nothing
              (Just aliceStaticPK)
              Nothing
              (Just noiseKNR0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceKN') <- writeHandshakeMsg aliceKN noiseKNI1 sampleHSPT
  let (hsptFromAlice1, bobKN') = readHandshakeMsg bobKN aliceToBob1 noiseKNR1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobKN' noiseKNR2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal aliceKN' bobToAlice1 noiseKNI2

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
-- Noise_NK

hsnNK :: ScrubbedBytes
hsnNK = makeHSN "Noise_NK"

doNK :: Plaintext -> Property
doNK pt = ioProperty $ do
  bobStaticKey@(_, bobStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceNK = handshakeState
                hsnNK
                Nothing
                Nothing
                (Just bobStaticPK)
                Nothing
                (Just noiseNKI0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobNK = handshakeState
              hsnNK
              (Just bobStaticKey)
              Nothing
              Nothing
              Nothing
              (Just noiseNKR0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceNK') <- writeHandshakeMsg aliceNK noiseNKI1 sampleHSPT
  let (hsptFromAlice1, bobNK') = readHandshakeMsg bobNK aliceToBob1 noiseNKR1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobNK' noiseNKR2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal aliceNK' bobToAlice1 noiseNKI2

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
-- Noise_KK

hsnKK :: ScrubbedBytes
hsnKK = makeHSN "Noise_KK"

doKK :: Plaintext -> Property
doKK pt = ioProperty $ do
  aliceStaticKey@(_, aliceStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)
  bobStaticKey@(_, bobStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceKK = handshakeState
                hsnKK
                (Just aliceStaticKey)
                Nothing
                (Just bobStaticPK)
                Nothing
                (Just noiseKKI0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobKK = handshakeState
              hsnKK
              (Just bobStaticKey)
              Nothing
              (Just aliceStaticPK)
              Nothing
              (Just noiseKKR0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceKK') <- writeHandshakeMsg aliceKK noiseKKI1 sampleHSPT
  let (hsptFromAlice1, bobKK') = readHandshakeMsg bobKK aliceToBob1 noiseKKR1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobKK' noiseKKR2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal aliceKK' bobToAlice1 noiseKKI2

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
-- Noise_NE

hsnNE :: ScrubbedBytes
hsnNE = makeHSN "Noise_NE"

doNE :: Plaintext -> Property
doNE pt = ioProperty $ do
  bobStaticKey@(_, bobStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)
  bobEphemeralKey@(_, bobEphemeralPK) <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceNE = handshakeState
                hsnNE
                Nothing
                Nothing
                (Just bobStaticPK)
                (Just bobEphemeralPK)
                (Just noiseNEI0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobNE = handshakeState
              hsnNE
              (Just bobStaticKey)
              (Just bobEphemeralKey)
              Nothing
              Nothing
              (Just noiseNER0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceNE') <- writeHandshakeMsg aliceNE noiseNEI1 sampleHSPT
  let (hsptFromAlice1, bobNE') = readHandshakeMsg bobNE aliceToBob1 noiseNER1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobNE' noiseNER2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal aliceNE' bobToAlice1 noiseNEI2

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
-- Noise_KE

hsnKE :: ScrubbedBytes
hsnKE = makeHSN "Noise_KE"

doKE :: Plaintext -> Property
doKE pt = ioProperty $ do
  aliceStaticKey@(_, aliceStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)
  bobStaticKey@(_, bobStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)
  bobEphemeralKey@(_, bobEphemeralPK) <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceKE = handshakeState
                hsnKE
                (Just aliceStaticKey)
                Nothing
                (Just bobStaticPK)
                (Just bobEphemeralPK)
                (Just noiseKEI0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobKE = handshakeState
              hsnKE
              (Just bobStaticKey)
              (Just bobEphemeralKey)
              (Just aliceStaticPK)
              Nothing
              (Just noiseKER0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceKE') <- writeHandshakeMsg aliceKE noiseKEI1 sampleHSPT
  let (hsptFromAlice1, bobKE') = readHandshakeMsg bobKE aliceToBob1 noiseKER1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobKE' noiseKER2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal aliceKE' bobToAlice1 noiseKEI2

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
-- Noise_NX

hsnNX :: ScrubbedBytes
hsnNX = makeHSN "Noise_NX"

doNX :: Plaintext -> Property
doNX pt = ioProperty $ do
  bobStaticKey <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceNX = handshakeState
                hsnNX
                Nothing
                Nothing
                Nothing
                Nothing
                Nothing :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobNX = handshakeState
              hsnNX
              (Just bobStaticKey)
              Nothing
              Nothing
              Nothing
              Nothing :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceNX') <- writeHandshakeMsg aliceNX noiseNXI1 sampleHSPT
  let (hsptFromAlice1, bobNX') = readHandshakeMsg bobNX aliceToBob1 noiseNXR1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobNX' noiseNXR2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal aliceNX' bobToAlice1 noiseNXI2

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
-- Noise_KX

hsnKX :: ScrubbedBytes
hsnKX = makeHSN "Noise_KX"

doKX :: Plaintext -> Property
doKX pt = ioProperty $ do
  aliceStaticKey@(_, aliceStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)
  bobStaticKey <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceKX = handshakeState
                hsnKX
                (Just aliceStaticKey)
                Nothing
                Nothing
                Nothing
                (Just noiseKXI0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobKX = handshakeState
              hsnKX
              (Just bobStaticKey)
              Nothing
              (Just aliceStaticPK)
              Nothing
              (Just noiseKXR0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceKX') <- writeHandshakeMsg aliceKX noiseKXI1 sampleHSPT
  let (hsptFromAlice1, bobKX') = readHandshakeMsg bobKX aliceToBob1 noiseKXR1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobKX' noiseKXR2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal aliceKX' bobToAlice1 noiseKXI2

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
  , testProperty "Noise_KN" $ property doKN
  , testProperty "Noise_NK" $ property doNK
  , testProperty "Noise_KK" $ property doKK
  , testProperty "Noise_NE" $ property doNE
  , testProperty "Noise_KE" $ property doKE
  , testProperty "Noise_NX" $ property doNX
  , testProperty "Noise_KX" $ property doKX
  ]
