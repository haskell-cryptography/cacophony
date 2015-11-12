{-# LANGUAGE OverloadedStrings #-}
module Handshake where

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Handshake
import Crypto.Noise.Hash
import Crypto.Noise.Types

import qualified HandshakeStates.C25519CCPSHA256 as C25519CCPSHA256
import qualified HandshakeStates.C25519CCPSHA512 as C25519CCPSHA512
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
    NoiseNN -> twoMessage C25519CCPSHA256.noiseNNIHS C25519CCPSHA256.noiseNNRHS
    NoiseKN -> twoMessage C25519CCPSHA256.noiseKNIHS C25519CCPSHA256.noiseKNRHS
    NoiseNK -> twoMessage C25519CCPSHA256.noiseNKIHS C25519CCPSHA256.noiseNKRHS
    NoiseKK -> twoMessage C25519CCPSHA256.noiseKKIHS C25519CCPSHA256.noiseKKRHS
    NoiseNE -> twoMessage C25519CCPSHA256.noiseNEIHS C25519CCPSHA256.noiseNERHS
    NoiseKE -> twoMessage C25519CCPSHA256.noiseKEIHS C25519CCPSHA256.noiseKERHS
    NoiseNX -> twoMessage C25519CCPSHA256.noiseNXIHS C25519CCPSHA256.noiseNXRHS
    NoiseKX -> twoMessage C25519CCPSHA256.noiseKXIHS C25519CCPSHA256.noiseKXRHS
    NoiseXN -> threeMessage C25519CCPSHA256.noiseXNIHS C25519CCPSHA256.noiseXNRHS
    NoiseIN -> twoMessage C25519CCPSHA256.noiseINIHS C25519CCPSHA256.noiseINRHS
    NoiseXK -> threeMessage C25519CCPSHA256.noiseXKIHS C25519CCPSHA256.noiseXKRHS
    NoiseIK -> twoMessage C25519CCPSHA256.noiseIKIHS C25519CCPSHA256.noiseIKRHS
    NoiseXE -> threeMessage C25519CCPSHA256.noiseXEIHS C25519CCPSHA256.noiseXERHS
    NoiseIE -> twoMessage C25519CCPSHA256.noiseIEIHS C25519CCPSHA256.noiseIERHS
    NoiseXX -> threeMessage C25519CCPSHA256.noiseXXIHS C25519CCPSHA256.noiseXXRHS
    NoiseIX -> twoMessage C25519CCPSHA256.noiseIXIHS C25519CCPSHA256.noiseIXRHS
    NoiseN  -> oneMessage C25519CCPSHA256.noiseNIHS C25519CCPSHA256.noiseNRHS
    NoiseK  -> oneMessage C25519CCPSHA256.noiseKIHS C25519CCPSHA256.noiseKRHS
    NoiseX  -> oneMessage C25519CCPSHA256.noiseXIHS C25519CCPSHA256.noiseXRHS

mkHandshakeProp' :: HandshakeType
                 -> Plaintext
                 -> Property
mkHandshakeProp' ht =
  case ht of
    NoiseNN -> twoMessage C25519CCPSHA512.noiseNNIHS C25519CCPSHA512.noiseNNRHS
    NoiseKN -> twoMessage C25519CCPSHA512.noiseKNIHS C25519CCPSHA512.noiseKNRHS
    NoiseNK -> twoMessage C25519CCPSHA512.noiseNKIHS C25519CCPSHA512.noiseNKRHS
    NoiseKK -> twoMessage C25519CCPSHA512.noiseKKIHS C25519CCPSHA512.noiseKKRHS
    NoiseNE -> twoMessage C25519CCPSHA512.noiseNEIHS C25519CCPSHA512.noiseNERHS
    NoiseKE -> twoMessage C25519CCPSHA512.noiseKEIHS C25519CCPSHA512.noiseKERHS
    NoiseNX -> twoMessage C25519CCPSHA512.noiseNXIHS C25519CCPSHA512.noiseNXRHS
    NoiseKX -> twoMessage C25519CCPSHA512.noiseKXIHS C25519CCPSHA512.noiseKXRHS
    NoiseXN -> threeMessage C25519CCPSHA512.noiseXNIHS C25519CCPSHA512.noiseXNRHS
    NoiseIN -> twoMessage C25519CCPSHA512.noiseINIHS C25519CCPSHA512.noiseINRHS
    NoiseXK -> threeMessage C25519CCPSHA512.noiseXKIHS C25519CCPSHA512.noiseXKRHS
    NoiseIK -> twoMessage C25519CCPSHA512.noiseIKIHS C25519CCPSHA512.noiseIKRHS
    NoiseXE -> threeMessage C25519CCPSHA512.noiseXEIHS C25519CCPSHA512.noiseXERHS
    NoiseIE -> twoMessage C25519CCPSHA512.noiseIEIHS C25519CCPSHA512.noiseIERHS
    NoiseXX -> threeMessage C25519CCPSHA512.noiseXXIHS C25519CCPSHA512.noiseXXRHS
    NoiseIX -> twoMessage C25519CCPSHA512.noiseIXIHS C25519CCPSHA512.noiseIXRHS
    NoiseN  -> oneMessage C25519CCPSHA512.noiseNIHS C25519CCPSHA512.noiseNRHS
    NoiseK  -> oneMessage C25519CCPSHA512.noiseKIHS C25519CCPSHA512.noiseKRHS
    NoiseX  -> oneMessage C25519CCPSHA512.noiseXIHS C25519CCPSHA512.noiseXRHS

oneMessage :: (Cipher c, Curve d, Hash h)
           => HandshakeState c d h
           -> HandshakeState c d h
           -> Plaintext
           -> Property
oneMessage ihs rhs pt = ioProperty $ do
  (aliceToBob1, csAlice1, _) <- writeMessageFinal ihs sampleHSPT
  let (hsptFromBob1, csBob1, _) = readMessageFinal rhs aliceToBob1

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
  (aliceToBob1, ihs') <- writeMessage ihs sampleHSPT
  let (hsptFromAlice1, rhs') = readMessage rhs aliceToBob1

  (bobToAlice1, csBob1, csBob2) <- writeMessageFinal rhs' sampleHSPT
  let (hsptFromBob1, csAlice1, csAlice2) = readMessageFinal ihs' bobToAlice1

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
    (aliceToBob1, ihs') <- writeMessage ihs sampleHSPT
    let (hsptFromAlice1, rhs') = readMessage rhs aliceToBob1

    (bobToAlice1, rhs'') <- writeMessage rhs' sampleHSPT
    let (hsptFromBob1, ihs'') = readMessage ihs' bobToAlice1

    (aliceToBob2, csAlice1, csAlice2) <- writeMessageFinal ihs'' sampleHSPT
    let (hsptFromBob2, csBob1, csBob2) = readMessageFinal rhs'' aliceToBob2

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
  [ testGroup "Curve25519-ChaChaPoly1305-SHA256"
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
  , testGroup "Curve25519-ChaChaPoly1305-SHA512"
    [ testProperty "Noise_NN" . property . mkHandshakeProp' $ NoiseNN
    , testProperty "Noise_KN" . property . mkHandshakeProp' $ NoiseKN
    , testProperty "Noise_NK" . property . mkHandshakeProp' $ NoiseNK
    , testProperty "Noise_KK" . property . mkHandshakeProp' $ NoiseKK
    , testProperty "Noise_NE" . property . mkHandshakeProp' $ NoiseNE
    , testProperty "Noise_KE" . property . mkHandshakeProp' $ NoiseKE
    , testProperty "Noise_NX" . property . mkHandshakeProp' $ NoiseNX
    , testProperty "Noise_KX" . property . mkHandshakeProp' $ NoiseKX
    , testProperty "Noise_XN" . property . mkHandshakeProp' $ NoiseXN
    , testProperty "Noise_IN" . property . mkHandshakeProp' $ NoiseIN
    , testProperty "Noise_XK" . property . mkHandshakeProp' $ NoiseXK
    , testProperty "Noise_IK" . property . mkHandshakeProp' $ NoiseIK
    , testProperty "Noise_XE" . property . mkHandshakeProp' $ NoiseXE
    , testProperty "Noise_IE" . property . mkHandshakeProp' $ NoiseIE
    , testProperty "Noise_XX" . property . mkHandshakeProp' $ NoiseXX
    , testProperty "Noise_IX" . property . mkHandshakeProp' $ NoiseIX
    , testProperty "Noise_N"  . property . mkHandshakeProp' $ NoiseN
    , testProperty "Noise_K"  . property . mkHandshakeProp' $ NoiseK
    , testProperty "Noise_X"  . property . mkHandshakeProp' $ NoiseX
    ]
  ]
