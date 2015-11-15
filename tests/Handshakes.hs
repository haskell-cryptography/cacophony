{-# LANGUAGE OverloadedStrings, RankNTypes, ScopedTypeVariables #-}
module Handshakes where

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

mkHandshakeProp :: forall c d h. (Cipher c, Curve d, Hash h)
                => HandshakeKeys d
                -> HandshakeType c d h
                -> Plaintext
                -> Property
mkHandshakeProp hks ht =
  let nni = noiseNNIHS hks :: HandshakeState c d h
      nnr = noiseNNRHS hks :: HandshakeState c d h
      kni = noiseKNIHS hks :: HandshakeState c d h
      knr = noiseKNRHS hks :: HandshakeState c d h
      nki = noiseNKIHS hks :: HandshakeState c d h
      nkr = noiseNKRHS hks :: HandshakeState c d h
      kki = noiseKKIHS hks :: HandshakeState c d h
      kkr = noiseKKRHS hks :: HandshakeState c d h
      nei = noiseNEIHS hks :: HandshakeState c d h
      ner = noiseNERHS hks :: HandshakeState c d h
      kei = noiseKEIHS hks :: HandshakeState c d h
      ker = noiseKERHS hks :: HandshakeState c d h
      nxi = noiseNXIHS hks :: HandshakeState c d h
      nxr = noiseNXRHS hks :: HandshakeState c d h
      kxi = noiseKXIHS hks :: HandshakeState c d h
      kxr = noiseKXRHS hks :: HandshakeState c d h
      xni = noiseXNIHS hks :: HandshakeState c d h
      xnr = noiseXNRHS hks :: HandshakeState c d h
      ini = noiseINIHS hks :: HandshakeState c d h
      inr = noiseINRHS hks :: HandshakeState c d h
      xki = noiseXKIHS hks :: HandshakeState c d h
      xkr = noiseXKRHS hks :: HandshakeState c d h
      iki = noiseIKIHS hks :: HandshakeState c d h
      ikr = noiseIKRHS hks :: HandshakeState c d h
      xei = noiseXEIHS hks :: HandshakeState c d h
      xer = noiseXERHS hks :: HandshakeState c d h
      iei = noiseIEIHS hks :: HandshakeState c d h
      ier = noiseIERHS hks :: HandshakeState c d h
      xxi = noiseXXIHS hks :: HandshakeState c d h
      xxr = noiseXXRHS hks :: HandshakeState c d h
      ixi = noiseIXIHS hks :: HandshakeState c d h
      ixr = noiseIXRHS hks :: HandshakeState c d h
      ni  = noiseNIHS  hks :: HandshakeState c d h
      nr  = noiseNRHS  hks :: HandshakeState c d h
      ki  = noiseKIHS  hks :: HandshakeState c d h
      kr  = noiseKRHS  hks :: HandshakeState c d h
      xi  = noiseXIHS  hks :: HandshakeState c d h
      xr  = noiseXRHS  hks :: HandshakeState c d h in
  case ht of
    NoiseNN -> twoMessage nni nnr
    NoiseKN -> twoMessage kni knr
    NoiseNK -> twoMessage nki nkr
    NoiseKK -> twoMessage kki kkr
    NoiseNE -> twoMessage nei ner
    NoiseKE -> twoMessage kei ker
    NoiseNX -> twoMessage nxi nxr
    NoiseKX -> twoMessage kxi kxr
    NoiseXN -> threeMessage xni xnr
    NoiseIN -> twoMessage ini inr
    NoiseXK -> threeMessage xki xkr
    NoiseIK -> twoMessage iki ikr
    NoiseXE -> threeMessage xei xer
    NoiseIE -> twoMessage iei ier
    NoiseXX -> threeMessage xxi xxr
    NoiseIX -> twoMessage ixi ixr
    NoiseN  -> oneMessage ni nr
    NoiseK  -> oneMessage ki kr
    NoiseX  -> oneMessage xi xr

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
  let hks = HandshakeKeys is25519 rs25519 re25519 in
  testGroup "Handshakes"
  [ testGroup "Curve25519-ChaChaPoly1305-SHA256"
    [ testProperty "Noise_NN" . property . mkHandshakeProp hks $ (NoiseNN :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_KN" . property . mkHandshakeProp hks $ (NoiseKN :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_NK" . property . mkHandshakeProp hks $ (NoiseNK :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_KK" . property . mkHandshakeProp hks $ (NoiseKK :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_NE" . property . mkHandshakeProp hks $ (NoiseNE :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_KE" . property . mkHandshakeProp hks $ (NoiseKE :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_NX" . property . mkHandshakeProp hks $ (NoiseNX :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_KX" . property . mkHandshakeProp hks $ (NoiseKX :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_XN" . property . mkHandshakeProp hks $ (NoiseXN :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_IN" . property . mkHandshakeProp hks $ (NoiseIN :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_XK" . property . mkHandshakeProp hks $ (NoiseXK :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_IK" . property . mkHandshakeProp hks $ (NoiseIK :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_XE" . property . mkHandshakeProp hks $ (NoiseXE :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_IE" . property . mkHandshakeProp hks $ (NoiseIE :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_XX" . property . mkHandshakeProp hks $ (NoiseXX :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_IX" . property . mkHandshakeProp hks $ (NoiseIX :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_N"  . property . mkHandshakeProp hks $ (NoiseN  :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_K"  . property . mkHandshakeProp hks $ (NoiseK  :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    , testProperty "Noise_X"  . property . mkHandshakeProp hks $ (NoiseX  :: HandshakeType ChaChaPoly1305 Curve25519 SHA256)
    ]
  , testGroup "Curve25519-ChaChaPoly1305-SHA512"
    [ testProperty "Noise_NN" . property . mkHandshakeProp hks $ (NoiseNN :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_KN" . property . mkHandshakeProp hks $ (NoiseKN :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_NK" . property . mkHandshakeProp hks $ (NoiseNK :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_KK" . property . mkHandshakeProp hks $ (NoiseKK :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_NE" . property . mkHandshakeProp hks $ (NoiseNE :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_KE" . property . mkHandshakeProp hks $ (NoiseKE :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_NX" . property . mkHandshakeProp hks $ (NoiseNX :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_KX" . property . mkHandshakeProp hks $ (NoiseKX :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_XN" . property . mkHandshakeProp hks $ (NoiseXN :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_IN" . property . mkHandshakeProp hks $ (NoiseIN :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_XK" . property . mkHandshakeProp hks $ (NoiseXK :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_IK" . property . mkHandshakeProp hks $ (NoiseIK :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_XE" . property . mkHandshakeProp hks $ (NoiseXE :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_IE" . property . mkHandshakeProp hks $ (NoiseIE :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_XX" . property . mkHandshakeProp hks $ (NoiseXX :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_IX" . property . mkHandshakeProp hks $ (NoiseIX :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_N"  . property . mkHandshakeProp hks $ (NoiseN  :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_K"  . property . mkHandshakeProp hks $ (NoiseK  :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    , testProperty "Noise_X"  . property . mkHandshakeProp hks $ (NoiseX  :: HandshakeType ChaChaPoly1305 Curve25519 SHA512)
    ]
   ]
