{-# LANGUAGE OverloadedStrings, RankNTypes, ScopedTypeVariables #-}
module Main where

import Control.DeepSeq   (($!!))
import Control.Exception (handle)
import Criterion.Main
import Data.Proxy

import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Handshake
import Crypto.Noise.Hash
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Types

import HandshakeStates
import Instances()

data HandshakeType c d h =
    NoiseNN
  | NoiseKN
  | NoiseNK
  | NoiseKK
  | NoiseNE
  | NoiseKE
  | NoiseNX
  | NoiseKXi
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

mkHandshakes :: forall c d h proxy. (Cipher c, Curve d, Hash h)
             => HandshakeKeys d
             -> HandshakeKeys d
             -> proxy (c, h)
             -> [Benchmark]
mkHandshakes ihks rhks _ =
  let nni, nnr, kni, knr, nki, nkr, kki, kkr, nei, ner, kei, ker, nxi, nxr,
        kxi, kxr, xni, xnr, ini, inr, xki, xkr, iki, ikr, xei, xer, iei, ier,
        xxi, xxr, ixi, ixr, ni, nr, ki, kr, xi, xr :: HandshakeState c d h
      nni = noiseNNIHS ihks
      nnr = noiseNNRHS rhks
      kni = noiseKNIHS ihks
      knr = noiseKNRHS rhks
      nki = noiseNKIHS ihks
      nkr = noiseNKRHS rhks
      kki = noiseKKIHS ihks
      kkr = noiseKKRHS rhks
      nei = noiseNEIHS ihks
      ner = noiseNERHS rhks
      kei = noiseKEIHS ihks
      ker = noiseKERHS rhks
      nxi = noiseNXIHS ihks
      nxr = noiseNXRHS rhks
      kxi = noiseKXIHS ihks
      kxr = noiseKXRHS rhks
      xni = noiseXNIHS ihks
      xnr = noiseXNRHS rhks
      ini = noiseINIHS ihks
      inr = noiseINRHS rhks
      xki = noiseXKIHS ihks
      xkr = noiseXKRHS rhks
      iki = noiseIKIHS ihks
      ikr = noiseIKRHS rhks
      xei = noiseXEIHS ihks
      xer = noiseXERHS rhks
      iei = noiseIEIHS ihks
      ier = noiseIERHS rhks
      xxi = noiseXXIHS ihks
      xxr = noiseXXRHS rhks
      ixi = noiseIXIHS ihks
      ixr = noiseIXRHS rhks
      ni  = noiseNIHS  ihks
      nr  = noiseNRHS  rhks
      ki  = noiseKIHS  ihks
      kr  = noiseKRHS  rhks
      xi  = noiseXIHS  ihks
      xr  = noiseXRHS  rhks in

   [ bench "NoisePSK_NN" $ whnfIO (twoMessage   nni nnr)
   , bench "NoisePSK_KN" $ whnfIO (twoMessage   kni knr)
   , bench "NoisePSK_NK" $ whnfIO (twoMessage   nki nkr)
   , bench "NoisePSK_KK" $ whnfIO (twoMessage   kki kkr)
   , bench "NoisePSK_NE" $ whnfIO (twoMessage   nei ner)
   , bench "NoisePSK_KE" $ whnfIO (twoMessage   kei ker)
   , bench "NoisePSK_NX" $ whnfIO (twoMessage   nxi nxr)
   , bench "NoisePSK_KX" $ whnfIO (twoMessage   kxi kxr)
   , bench "NoisePSK_XN" $ whnfIO (threeMessage xni xnr)
   , bench "NoisePSK_IN" $ whnfIO (twoMessage   ini inr)
   , bench "NoisePSK_XK" $ whnfIO (threeMessage xki xkr)
   , bench "NoisePSK_IK" $ whnfIO (twoMessage   iki ikr)
   , bench "NoisePSK_XE" $ whnfIO (threeMessage xei xer)
   , bench "NoisePSK_IE" $ whnfIO (twoMessage   iei ier)
   , bench "NoisePSK_XX" $ whnfIO (threeMessage xxi xxr)
   , bench "NoisePSK_IX" $ whnfIO (twoMessage   ixi ixr)
   , bench "NoisePSK_N"  $ whnfIO (oneMessage   ni  nr )
   , bench "NoisePSK_K"  $ whnfIO (oneMessage   ki  kr )
   , bench "NoisePSK_X"  $ whnfIO (oneMessage   xi  xr )
   ]

oneMessage :: (Cipher c, Curve d, Hash h)
           => HandshakeState c d h
           -> HandshakeState c d h
           -> IO Plaintext
oneMessage ihs rhs = handle (\(_ :: NoiseException) -> return "") $ do
  (aliceToBob1, csAlice1, _) <- writeMessageFinal ihs ""
  let (_, csBob1, _) = readMessageFinal rhs aliceToBob1
      x = decrypt csBob1 . encrypt csAlice1 $ ""

  return $!! x

  where
      encrypt cs p  = fst $ encryptPayload p  cs
      decrypt cs ct = fst $ decryptPayload ct cs

twoMessage :: (Cipher c, Curve d, Hash h)
           => HandshakeState c d h
           -> HandshakeState c d h
           -> IO (Plaintext, Plaintext)
twoMessage ihs rhs = handle (\(_ :: NoiseException) -> return ("", "")) $ do
  (aliceToBob1, ihs') <- writeMessage ihs ""
  let (_, rhs') = readMessage rhs aliceToBob1

  (bobToAlice1, csBob1, csBob2) <- writeMessageFinal rhs' ""
  let (_, csAlice1, csAlice2) = readMessageFinal ihs' bobToAlice1
      x = decrypt csBob1 . encrypt csAlice1 $ ""
      y = decrypt csAlice2 . encrypt csBob2 $ ""

  return $!! (x, y)

  where
      encrypt cs p  = fst $ encryptPayload p  cs
      decrypt cs ct = fst $ decryptPayload ct cs

threeMessage :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> HandshakeState c d h
             -> IO (Plaintext, Plaintext)
threeMessage ihs rhs = handle (\(_ :: NoiseException) -> return ("", "")) $ do
  (aliceToBob1, ihs') <- writeMessage ihs ""
  let (_, rhs') = readMessage rhs aliceToBob1

  (bobToAlice1, rhs'') <- writeMessage rhs' ""
  let (_, ihs'') = readMessage ihs' bobToAlice1

  (aliceToBob2, csAlice1, csAlice2) <- writeMessageFinal ihs'' ""
  let (_, csBob1, csBob2) = readMessageFinal rhs'' aliceToBob2
      x = decrypt csBob1 . encrypt csAlice1 $ ""
      y = decrypt csAlice2 . encrypt csBob2 $ ""

  return $!! (x, y)

  where
      encrypt cs p  = fst $ encryptPayload p  cs
      decrypt cs ct = fst $ decryptPayload ct cs

main :: IO ()
main =
  let p    = Just "cacophony"
      p'   = Just "not cacophony"
      hks  = HandshakeKeys p  is25519 rs25519 re25519
      hks' = HandshakeKeys p' is25519 rs25519 re25519 in
  defaultMain
  [ bgroup "Curve25519-ChaChaPoly1305-SHA256"
    [ bgroup "with valid PSK"
      (mkHandshakes hks hks (Proxy :: Proxy (ChaChaPoly1305, SHA256)))
    , bgroup "with invalid PSK"
      (mkHandshakes hks hks' (Proxy :: Proxy (ChaChaPoly1305, SHA256)))
    ]
  ]
