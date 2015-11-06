{-# LANGUAGE OverloadedStrings #-}
module Handshake where

import Data.ByteString (ByteString)

import Crypto.Noise.Descriptors
import Crypto.Noise.Handshake
import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Hash
import Crypto.Noise.Types

import HandshakeStates
import Imports
import Instances()

data HandshakeType = NoiseNN
                   | NoiseKN
                   | NoiseNK
                   | NoiseKK
                   | NoiseNE
                   | NoiseKE
                   | NoiseNX
                   | NoiseKX
                   | NoiseXN
                   | NoiseIN
                   | NoiseXK
                   | NoiseIK
                   | NoiseXE
                   | NoiseIE
                   | NoiseXX
                   | NoiseIX
                   | NoiseN
                   | NoiseK
                   | NoiseX

sampleHSPT :: Plaintext
sampleHSPT = Plaintext . bsToSB' $ "cacophony"

mkHandshakeProp :: HandshakeType
                -> Plaintext
                -> Property
mkHandshakeProp ht =
  case ht of
    NoiseNN -> twoMessage noiseNNIHS noiseNNRHS noiseNNI1 noiseNNR1 noiseNNR2 noiseNNI2
    NoiseKN -> twoMessage noiseKNIHS noiseKNRHS noiseKNI1 noiseKNR1 noiseKNR2 noiseKNI2
    NoiseNK -> twoMessage noiseNKIHS noiseNKRHS noiseNKI1 noiseNKR1 noiseNKR2 noiseNKI2
    NoiseKK -> twoMessage noiseKKIHS noiseKKRHS noiseKKI1 noiseKKR1 noiseKKR2 noiseKKI2
    NoiseNE -> twoMessage noiseNEIHS noiseNERHS noiseNEI1 noiseNER1 noiseNER2 noiseNEI2
    NoiseKE -> twoMessage noiseKEIHS noiseKERHS noiseKEI1 noiseKER1 noiseKER2 noiseKEI2
    NoiseNX -> twoMessage noiseNXIHS noiseNXRHS noiseNXI1 noiseNXR1 noiseNXR2 noiseNXI2
    NoiseKX -> twoMessage noiseKXIHS noiseKXRHS noiseKXI1 noiseKXR1 noiseKXR2 noiseKXI2
    NoiseXN -> threeMessage noiseXNIHS noiseXNRHS noiseXNI1 noiseXNR1 noiseXNR2 noiseXNI2 noiseXNI3 noiseXNR3
    NoiseIN -> twoMessage noiseINIHS noiseINRHS noiseINI1 noiseINR1 noiseINR2 noiseINI2
    NoiseXK -> threeMessage noiseXKIHS noiseXKRHS noiseXKI1 noiseXKR1 noiseXKR2 noiseXKI2 noiseXKI3 noiseXKR3
    NoiseIK -> twoMessage noiseIKIHS noiseIKRHS noiseIKI1 noiseIKR1 noiseIKR2 noiseIKI2
    NoiseXE -> threeMessage noiseXEIHS noiseXERHS noiseXEI1 noiseXER1 noiseXER2 noiseXEI2 noiseXEI3 noiseXER3
    NoiseIE -> twoMessage noiseIEIHS noiseIERHS noiseIEI1 noiseIER1 noiseIER2 noiseIEI2
    NoiseXX -> threeMessage noiseXXIHS noiseXXRHS noiseXXI1 noiseXXR1 noiseXXR2 noiseXXI2 noiseXXI3 noiseXXR3
    NoiseIX -> twoMessage noiseIXIHS noiseIXRHS noiseIXI1 noiseIXR1 noiseIXR2 noiseIXI2
    NoiseN  -> oneMessage noiseNIHS noiseNRHS noiseNI1 noiseNR1
    NoiseK  -> oneMessage noiseKIHS noiseKRHS noiseKI1 noiseKR1
    NoiseX  -> oneMessage noiseXIHS noiseXRHS noiseXI1 noiseXR1

oneMessage :: (Cipher c, Curve d, Hash h)
           => HandshakeState c d h
           -> HandshakeState c d h
           -> DescriptorIO c d h ByteString
           -> (ByteString -> Descriptor c d h ByteString)
           -> Plaintext
           -> Property
oneMessage ihs rhs noiseI1 noiseR1 pt = ioProperty $ do
  (aliceToBob1, csAlice1, _) <- writeHandshakeMsgFinal ihs noiseI1 sampleHSPT
  let (hsptFromBob1, csBob1, _) = readHandshakeMsgFinal rhs aliceToBob1 noiseR1

  return $ conjoin
    [ (decrypt csBob1 . encrypt csAlice1) pt === pt
    , (decrypt csAlice1 . encrypt csBob1) pt === pt
    , hsptFromBob1 === sampleHSPT
    ]

  where
    encrypt cs p  = fst $ encryptPayload p  cs
    decrypt cs ct = fst $ decryptPayload ct cs

twoMessage :: (Cipher c, Curve d, Hash h)
           => HandshakeState c d h
           -> HandshakeState c d h
           -> DescriptorIO c d h ByteString
           -> (ByteString -> Descriptor c d h ByteString)
           -> DescriptorIO c d h ByteString
           -> (ByteString -> Descriptor c d h ByteString)
           -> Plaintext
           -> Property
twoMessage ihs rhs noiseI1 noiseR1 noiseR2 noiseI2 pt = ioProperty $ do
  (aliceToBob1, ihs') <- writeHandshakeMsg ihs noiseI1 sampleHSPT
  let (hsptFromAlice1, rhs') = readHandshakeMsg rhs aliceToBob1 noiseR1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal rhs' noiseR2 sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal ihs' bobToAlice1 noiseI2

  return $ conjoin
    [ (decrypt csBob1 . encrypt csAlice1) pt === pt
    , (decrypt csBob2 . encrypt csAlice2) pt === pt
    , (decrypt csAlice1 . encrypt csBob1) pt === pt
    , (decrypt csAlice2 . encrypt csBob2) pt === pt
    , hsptFromAlice1 === sampleHSPT
    , hsptFromBob1   === sampleHSPT
    ]

  where
    encrypt cs p  = fst $ encryptPayload p  cs
    decrypt cs ct = fst $ decryptPayload ct cs

threeMessage :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> HandshakeState c d h
             -> DescriptorIO c d h ByteString
             -> (ByteString -> Descriptor c d h ByteString)
             -> DescriptorIO c d h ByteString
             -> (ByteString -> Descriptor c d h ByteString)
             -> DescriptorIO c d h ByteString
             -> (ByteString -> Descriptor c d h ByteString)
             -> Plaintext
             -> Property
threeMessage ihs rhs noiseI1 noiseR1 noiseR2 noiseI2 noiseI3 noiseR3 pt =
  ioProperty $ do
    (aliceToBob1, ihs') <- writeHandshakeMsg ihs noiseI1 sampleHSPT
    let (hsptFromAlice1, rhs') = readHandshakeMsg rhs aliceToBob1 noiseR1

    (bobToAlice1, rhs'') <- writeHandshakeMsg rhs' noiseR2 sampleHSPT
    let (hsptFromBob1, ihs'') = readHandshakeMsg ihs' bobToAlice1 noiseI2

    (aliceToBob2, csAlice1, csAlice2) <- writeHandshakeMsgFinal ihs'' noiseI3 sampleHSPT
    let (hsptFromBob2, csBob1, csBob2) = readHandshakeMsgFinal rhs'' aliceToBob2 noiseR3

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
      encrypt cs p  = fst $ encryptPayload p  cs
      decrypt cs ct = fst $ decryptPayload ct cs

tests :: TestTree
tests = testGroup "Handshakes"
  [ testProperty "Noise_NN" . property . mkHandshakeProp $ NoiseNN
  , testProperty "Noise_KN" . property . mkHandshakeProp $ NoiseKN
  , testProperty "Noise_NK" . property . mkHandshakeProp $ NoiseNK
  , testProperty "Noise_KK" . property . mkHandshakeProp $ NoiseKK
  , testProperty "Noise_NE" . property . mkHandshakeProp $ NoiseNE
  , testProperty "Noise_KE" . property . mkHandshakeProp $ NoiseKE
  , testProperty "Noise_NX" . property . mkHandshakeProp $ NoiseNX
  , testProperty "Noise_KX" . property . mkHandshakeProp $ NoiseKX
  , testProperty "Noise_XN" . property . mkHandshakeProp $ NoiseXN
  , testProperty "Noise_IN" . property . mkHandshakeProp $ NoiseIN
  , testProperty "Noise_XK" . property . mkHandshakeProp $ NoiseXK
  , testProperty "Noise_IK" . property . mkHandshakeProp $ NoiseIK
  , testProperty "Noise_XE" . property . mkHandshakeProp $ NoiseXE
  , testProperty "Noise_IE" . property . mkHandshakeProp $ NoiseIE
  , testProperty "Noise_XX" . property . mkHandshakeProp $ NoiseXX
  , testProperty "Noise_IX" . property . mkHandshakeProp $ NoiseIX
  , testProperty "Noise_N"  . property . mkHandshakeProp $ NoiseN
  , testProperty "Noise_K"  . property . mkHandshakeProp $ NoiseK
  , testProperty "Noise_X"  . property . mkHandshakeProp $ NoiseX
  ]
