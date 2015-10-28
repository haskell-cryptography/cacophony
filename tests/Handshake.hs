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

doNN :: Plaintext -> Property
doNN pt = ioProperty $ do
  let aliceNN = handshakeState hsnNN Nothing Nothing Nothing Nothing Nothing
                :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
      bobNN   = handshakeState hsnNN Nothing Nothing Nothing Nothing Nothing
                :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
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

--------------------------------------------------------------------------------
-- Noise_XN

hsnXN :: ScrubbedBytes
hsnXN = makeHSN "Noise_XN"

doXN :: Plaintext -> Property
doXN pt = ioProperty $ do
  aliceStaticKey <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceXN = handshakeState
                hsnXN
                (Just aliceStaticKey)
                Nothing
                Nothing
                Nothing
                Nothing :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobXN = handshakeState
              hsnXN
              Nothing
              Nothing
              Nothing
              Nothing
              Nothing :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceXN') <- writeHandshakeMsg aliceXN noiseXNI1 sampleHSPT
  let (hsptFromAlice1, bobXN') = readHandshakeMsg bobXN aliceToBob1 noiseXNR1

  (bobToAlice1, bobXN'') <- writeHandshakeMsg bobXN' noiseXNR2 sampleHSPT
  let (hsptFromBob1, aliceXN'') = readHandshakeMsg aliceXN' bobToAlice1 noiseXNI2

  (aliceToBob2, csAlice1, csAlice2) <- writeHandshakeMsgFinal aliceXN'' noiseXNI3 sampleHSPT
  let (hsptFromBob2, csBob1, csBob2) = readHandshakeMsgFinal bobXN'' aliceToBob2 noiseXNR3

  return $ conjoin
    [ (decrypt csBob1 . encrypt csAlice1) pt === pt
    , (decrypt csBob2 . encrypt csAlice2) pt === pt
    , (decrypt csAlice1 . encrypt csBob1) pt === pt
    , (decrypt csAlice2 . encrypt csBob2) pt === pt
    , hsptFromAlice1 === sampleHSPT
    , hsptFromBob1   === sampleHSPT
    , hsptFromBob2   === sampleHSPT
    ]

  where
    encrypt cs p = fst $ encryptPayload p cs
    decrypt cs ct = fst $ decryptPayload ct cs

--------------------------------------------------------------------------------
-- Noise_IN

hsnIN :: ScrubbedBytes
hsnIN = makeHSN "Noise_IN"

doIN :: Plaintext -> Property
doIN pt = ioProperty $ do
  aliceStaticKey <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceIN = handshakeState
                hsnIN
                (Just aliceStaticKey)
                Nothing
                Nothing
                Nothing
                Nothing :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobIN = handshakeState
              hsnIN
              Nothing
              Nothing
              Nothing
              Nothing
              Nothing :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceIN') <- writeHandshakeMsg aliceIN noiseINI1 sampleHSPT
  let (hsptFromAlice1, bobIN') = readHandshakeMsg bobIN aliceToBob1 noiseINR1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobIN' noiseINR2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal aliceIN' bobToAlice1 noiseINI2

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
-- Noise_XK

hsnXK :: ScrubbedBytes
hsnXK = makeHSN "Noise_XK"

doXK :: Plaintext -> Property
doXK pt = ioProperty $ do
  aliceStaticKey <- curveGenKey :: IO (KeyPair Curve25519)
  bobStaticKey@(_, bobStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceXK = handshakeState
                hsnXK
                (Just aliceStaticKey)
                Nothing
                (Just bobStaticPK)
                Nothing
                (Just noiseXKI0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobXK = handshakeState
              hsnXK
              (Just bobStaticKey)
              Nothing
              Nothing
              Nothing
              (Just noiseXKR0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceXK') <- writeHandshakeMsg aliceXK noiseXKI1 sampleHSPT
  let (hsptFromAlice1, bobXK') = readHandshakeMsg bobXK aliceToBob1 noiseXKR1

  (bobToAlice1, bobXK'') <- writeHandshakeMsg bobXK' noiseXKR2 sampleHSPT
  let (hsptFromBob1, aliceXK'') = readHandshakeMsg aliceXK' bobToAlice1 noiseXKI2

  (aliceToBob2, csAlice1, csAlice2) <- writeHandshakeMsgFinal aliceXK'' noiseXKI3 sampleHSPT
  let (hsptFromBob2, csBob1, csBob2) = readHandshakeMsgFinal bobXK'' aliceToBob2 noiseXKR3

  return $ conjoin
    [ (decrypt csBob1 . encrypt csAlice1) pt === pt
    , (decrypt csBob2 . encrypt csAlice2) pt === pt
    , (decrypt csAlice1 . encrypt csBob1) pt === pt
    , (decrypt csAlice2 . encrypt csBob2) pt === pt
    , hsptFromAlice1 === sampleHSPT
    , hsptFromBob1   === sampleHSPT
    , hsptFromBob2   === sampleHSPT
    ]

  where
    encrypt cs p = fst $ encryptPayload p cs
    decrypt cs ct = fst $ decryptPayload ct cs

--------------------------------------------------------------------------------
-- Noise_IK

hsnIK :: ScrubbedBytes
hsnIK = makeHSN "Noise_IK"

doIK :: Plaintext -> Property
doIK pt = ioProperty $ do
  aliceStaticKey@(_, aliceStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)
  bobStaticKey@(_, bobStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceIK = handshakeState
                hsnIK
                (Just aliceStaticKey)
                Nothing
                (Just bobStaticPK)
                Nothing
                (Just noiseIKI0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobIK = handshakeState
              hsnIK
              (Just bobStaticKey)
              Nothing
              (Just aliceStaticPK)
              Nothing
              (Just noiseIKR0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceIK') <- writeHandshakeMsg aliceIK noiseIKI1 sampleHSPT
  let (hsptFromAlice1, bobIK') = readHandshakeMsg bobIK aliceToBob1 noiseIKR1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobIK' noiseIKR2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal aliceIK' bobToAlice1 noiseIKI2

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
-- Noise_XE

hsnXE :: ScrubbedBytes
hsnXE = makeHSN "Noise_XE"

doXE :: Plaintext -> Property
doXE pt = ioProperty $ do
  aliceStaticKey <- curveGenKey :: IO (KeyPair Curve25519)
  bobStaticKey@(_, bobStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)
  bobEphemeralKey@(_, bobEphemeralPK) <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceXE = handshakeState
                hsnXE
                (Just aliceStaticKey)
                Nothing
                (Just bobStaticPK)
                (Just bobEphemeralPK)
                (Just noiseXEI0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobXE = handshakeState
              hsnXE
              (Just bobStaticKey)
              (Just bobEphemeralKey)
              Nothing
              Nothing
              (Just noiseXER0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceXE') <- writeHandshakeMsg aliceXE noiseXEI1 sampleHSPT
  let (hsptFromAlice1, bobXE') = readHandshakeMsg bobXE aliceToBob1 noiseXER1

  (bobToAlice1, bobXE'') <- writeHandshakeMsg bobXE' noiseXER2 sampleHSPT
  let (hsptFromBob1, aliceXE'') = readHandshakeMsg aliceXE' bobToAlice1 noiseXEI2

  (aliceToBob2, csAlice1, csAlice2) <- writeHandshakeMsgFinal aliceXE'' noiseXEI3 sampleHSPT
  let (hsptFromBob2, csBob1, csBob2) = readHandshakeMsgFinal bobXE'' aliceToBob2 noiseXER3

  return $ conjoin
    [ (decrypt csBob1 . encrypt csAlice1) pt === pt
    , (decrypt csBob2 . encrypt csAlice2) pt === pt
    , (decrypt csAlice1 . encrypt csBob1) pt === pt
    , (decrypt csAlice2 . encrypt csBob2) pt === pt
    , hsptFromAlice1 === sampleHSPT
    , hsptFromBob1   === sampleHSPT
    , hsptFromBob2   === sampleHSPT
    ]

  where
    encrypt cs p = fst $ encryptPayload p cs
    decrypt cs ct = fst $ decryptPayload ct cs

--------------------------------------------------------------------------------
-- Noise_IE

hsnIE :: ScrubbedBytes
hsnIE = makeHSN "Noise_IE"

doIE :: Plaintext -> Property
doIE pt = ioProperty $ do
  aliceStaticKey@(_, aliceStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)
  bobStaticKey@(_, bobStaticPK) <- curveGenKey :: IO (KeyPair Curve25519)
  bobEphemeralKey@(_, bobEphemeralPK) <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceIE = handshakeState
                hsnIE
                (Just aliceStaticKey)
                Nothing
                (Just bobStaticPK)
                (Just bobEphemeralPK)
                (Just noiseIEI0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobIE = handshakeState
              hsnIE
              (Just bobStaticKey)
              (Just bobEphemeralKey)
              (Just aliceStaticPK)
              Nothing
              (Just noiseIER0) :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceIE') <- writeHandshakeMsg aliceIE noiseIEI1 sampleHSPT
  let (hsptFromAlice1, bobIE') = readHandshakeMsg bobIE aliceToBob1 noiseIER1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobIE' noiseIER2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal aliceIE' bobToAlice1 noiseIEI2

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
-- Noise_XX

hsnXX :: ScrubbedBytes
hsnXX = makeHSN "Noise_XX"

doXX :: Plaintext -> Property
doXX pt = ioProperty $ do
  aliceStaticKey <- curveGenKey :: IO (KeyPair Curve25519)
  bobStaticKey <- curveGenKey :: IO (KeyPair Curve25519)

  let aliceXX = handshakeState
                hsnXX
                (Just aliceStaticKey)
                Nothing
                Nothing
                Nothing
                Nothing :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

      bobXX = handshakeState
              hsnXX
              (Just bobStaticKey)
              Nothing
              Nothing
              Nothing
              Nothing :: HandshakeState ChaChaPoly1305 Curve25519 SHA256

  (aliceToBob1, aliceXX') <- writeHandshakeMsg aliceXX noiseXXI1 sampleHSPT
  let (hsptFromAlice1, bobXX') = readHandshakeMsg bobXX aliceToBob1 noiseXXR1

  (bobToAlice1, bobXX'') <- writeHandshakeMsg bobXX' noiseXXR2 sampleHSPT
  let (hsptFromBob1, aliceXX'') = readHandshakeMsg aliceXX' bobToAlice1 noiseXXI2

  (aliceToBob2, csAlice1, csAlice2) <- writeHandshakeMsgFinal aliceXX'' noiseXXI3 sampleHSPT
  let (hsptFromBob2, csBob1, csBob2) = readHandshakeMsgFinal bobXX'' aliceToBob2 noiseXXR3

  return $ conjoin
    [ (decrypt csBob1 . encrypt csAlice1) pt === pt
    , (decrypt csBob2 . encrypt csAlice2) pt === pt
    , (decrypt csAlice1 . encrypt csBob1) pt === pt
    , (decrypt csAlice2 . encrypt csBob2) pt === pt
    , hsptFromAlice1 === sampleHSPT
    , hsptFromBob1   === sampleHSPT
    , hsptFromBob2   === sampleHSPT
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
  , testProperty "Noise_XN" $ property doXN
  , testProperty "Noise_IN" $ property doIN
  , testProperty "Noise_XK" $ property doXK
  , testProperty "Noise_IK" $ property doIK
  , testProperty "Noise_XE" $ property doXE
  , testProperty "Noise_IE" $ property doIE
  , testProperty "Noise_XX" $ property doXX
  ]
