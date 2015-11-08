{-# LANGUAGE OverloadedStrings #-}
module Handshake where

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Handshake
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
    NoiseNN -> twoMessage noiseNNIHS noiseNNRHS
    NoiseKN -> twoMessage noiseKNIHS noiseKNRHS
    NoiseNK -> twoMessage noiseNKIHS noiseNKRHS
    NoiseKK -> twoMessage noiseKKIHS noiseKKRHS
    NoiseNE -> twoMessage noiseNEIHS noiseNERHS
    NoiseKE -> twoMessage noiseKEIHS noiseKERHS
    NoiseNX -> twoMessage noiseNXIHS noiseNXRHS
    NoiseKX -> twoMessage noiseKXIHS noiseKXRHS
    NoiseXN -> threeMessage noiseXNIHS noiseXNRHS
    NoiseIN -> twoMessage noiseINIHS noiseINRHS
    NoiseXK -> threeMessage noiseXKIHS noiseXKRHS
    NoiseIK -> twoMessage noiseIKIHS noiseIKRHS
    NoiseXE -> threeMessage noiseXEIHS noiseXERHS
    NoiseIE -> twoMessage noiseIEIHS noiseIERHS
    NoiseXX -> threeMessage noiseXXIHS noiseXXRHS
    NoiseIX -> twoMessage noiseIXIHS noiseIXRHS
    NoiseN  -> oneMessage noiseNIHS noiseNRHS
    NoiseK  -> oneMessage noiseKIHS noiseKRHS
    NoiseX  -> oneMessage noiseXIHS noiseXRHS

oneMessage :: (Cipher c, Curve d, Hash h)
           => HandshakeState c d h
           -> HandshakeState c d h
           -> Plaintext
           -> Property
oneMessage ihs rhs pt = ioProperty $ do
  (aliceToBob1, csAlice1, _) <- writeHandshakeMsgFinal ihs sampleHSPT
  let (hsptFromBob1, csBob1, _) = readHandshakeMsgFinal rhs aliceToBob1

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
           -> Plaintext
           -> Property
twoMessage ihs rhs pt = ioProperty $ do
  (aliceToBob1, ihs') <- writeHandshakeMsg ihs sampleHSPT
  let (hsptFromAlice1, rhs') = readHandshakeMsg rhs aliceToBob1

  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal rhs' sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readHandshakeMsgFinal ihs' bobToAlice1

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
             -> Plaintext
             -> Property
threeMessage ihs rhs pt =
  ioProperty $ do
    (aliceToBob1, ihs') <- writeHandshakeMsg ihs sampleHSPT
    let (hsptFromAlice1, rhs') = readHandshakeMsg rhs aliceToBob1

    (bobToAlice1, rhs'') <- writeHandshakeMsg rhs' sampleHSPT
    let (hsptFromBob1, ihs'') = readHandshakeMsg ihs' bobToAlice1

    (aliceToBob2, csAlice1, csAlice2) <- writeHandshakeMsgFinal ihs'' sampleHSPT
    let (hsptFromBob2, csBob1, csBob2) = readHandshakeMsgFinal rhs'' aliceToBob2

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
