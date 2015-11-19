{-# LANGUAGE OverloadedStrings, RankNTypes, ScopedTypeVariables #-}
module Handshakes where

import Data.Proxy

import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Handshake
import Crypto.Noise.Hash
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Hash.SHA512
import Crypto.Noise.Types

import Imports
import Instances()

import HandshakeStates

data HandshakeType c d h =
    NoiseNN
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

is25519 :: KeyPair Curve25519
is25519 = curveBytesToPair . bsToSB' $ "I\f\232\218A\210\230\147\FS\222\167\v}l\243!\168.\ESC\t\SYN\"\169\179A`\DC28\211\169tC"

rs25519 :: KeyPair Curve25519
rs25519 = curveBytesToPair . bsToSB' $ "\ETB\157\&7\DC2\252\NUL\148\172\148\133\218\207\&8\221y\144\209\168FX\224Ser_\178|\153.\FSg&"

re25519 :: KeyPair Curve25519
re25519 = curveBytesToPair . bsToSB' $ "<\231\151\151\180\217\146\DLEI}\160N\163iKc\162\210Y\168R\213\206&gm\169r\SUB[\\'"

sampleHSPT :: Plaintext
sampleHSPT = Plaintext . bsToSB' $ "cacophony"

mkHandshakeProps :: forall c d h proxy. (Cipher c, Curve d, Hash h)
                 => HandshakeKeys d
                 -> proxy (c, h)
                 -> [TestTree]
mkHandshakeProps hks _ =
  let nni, nnr, kni, knr, nki, nkr, kki, kkr, nei, ner, kei, ker, nxi, nxr,
        kxi, kxr, xni, xnr, ini, inr, xki, xkr, iki, ikr, xei, xer, iei, ier,
        xxi, xxr, ixi, ixr, ni, nr, ki, kr, xi, xr :: HandshakeState c d h
      nni = noiseNNIHS hks
      nnr = noiseNNRHS hks
      kni = noiseKNIHS hks
      knr = noiseKNRHS hks
      nki = noiseNKIHS hks
      nkr = noiseNKRHS hks
      kki = noiseKKIHS hks
      kkr = noiseKKRHS hks
      nei = noiseNEIHS hks
      ner = noiseNERHS hks
      kei = noiseKEIHS hks
      ker = noiseKERHS hks
      nxi = noiseNXIHS hks
      nxr = noiseNXRHS hks
      kxi = noiseKXIHS hks
      kxr = noiseKXRHS hks
      xni = noiseXNIHS hks
      xnr = noiseXNRHS hks
      ini = noiseINIHS hks
      inr = noiseINRHS hks
      xki = noiseXKIHS hks
      xkr = noiseXKRHS hks
      iki = noiseIKIHS hks
      ikr = noiseIKRHS hks
      xei = noiseXEIHS hks
      xer = noiseXERHS hks
      iei = noiseIEIHS hks
      ier = noiseIERHS hks
      xxi = noiseXXIHS hks
      xxr = noiseXXRHS hks
      ixi = noiseIXIHS hks
      ixr = noiseIXRHS hks
      ni  = noiseNIHS  hks
      nr  = noiseNRHS  hks
      ki  = noiseKIHS  hks
      kr  = noiseKRHS  hks
      xi  = noiseXIHS  hks
      xr  = noiseXRHS  hks in

   [ testProperty "Noise_NN" (property (twoMessage   nni nnr))
   , testProperty "Noise_KN" (property (twoMessage   kni knr))
   , testProperty "Noise_NK" (property (twoMessage   nki nkr))
   , testProperty "Noise_KK" (property (twoMessage   kki kkr))
   , testProperty "Noise_NE" (property (twoMessage   nei ner))
   , testProperty "Noise_KE" (property (twoMessage   kei ker))
   , testProperty "Noise_NX" (property (twoMessage   nxi nxr))
   , testProperty "Noise_KX" (property (twoMessage   kxi kxr))
   , testProperty "Noise_XN" (property (threeMessage xni xnr))
   , testProperty "Noise_IN" (property (twoMessage   ini inr))
   , testProperty "Noise_XK" (property (threeMessage xki xkr))
   , testProperty "Noise_IK" (property (twoMessage   iki ikr))
   , testProperty "Noise_XE" (property (threeMessage xei xer))
   , testProperty "Noise_IE" (property (twoMessage   iei ier))
   , testProperty "Noise_XX" (property (threeMessage xxi xxr))
   , testProperty "Noise_IX" (property (twoMessage   ixi ixr))
   , testProperty "Noise_N"  (property (oneMessage   ni  nr ))
   , testProperty "Noise_K"  (property (oneMessage   ki  kr ))
   , testProperty "Noise_X"  (property (oneMessage   xi  xr ))
   ]

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
tests =
  let p    = Just "cacophony"
      hks  = HandshakeKeys p is25519 rs25519 re25519
      hks' = HandshakeKeys Nothing is25519 rs25519 re25519 in
  testGroup "Handshakes"
  [ testGroup "without PSK"
    [ testGroup "Curve25519-ChaChaPoly1305-SHA256"
      (mkHandshakeProps hks (Proxy :: Proxy (ChaChaPoly1305, SHA256)))
    , testGroup "Curve25519-ChaChaPoly1305-SHA512"
      (mkHandshakeProps hks (Proxy :: Proxy (ChaChaPoly1305, SHA512)))
    ]
  , testGroup "with PSK"
    [ testGroup "Curve25519-ChaChaPoly1305-SHA256"
      (mkHandshakeProps hks' (Proxy :: Proxy (ChaChaPoly1305, SHA256)))
    , testGroup "Curve25519-ChaChaPoly1305-SHA512"
      (mkHandshakeProps hks' (Proxy :: Proxy (ChaChaPoly1305, SHA512)))
    ]
  ]
