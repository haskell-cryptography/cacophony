{-# LANGUAGE OverloadedStrings, RankNTypes, ScopedTypeVariables #-}
module Main where

import Control.Concurrent       (threadDelay)
import Control.Concurrent.Async (concurrently)
import Control.Concurrent.Chan
import Control.DeepSeq          (($!!))
import Criterion.Main
import Data.ByteString          (ByteString)
import Data.Proxy

import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.AESGCM
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Handshake
import Crypto.Noise.Hash
import Crypto.Noise.Hash.BLAKE2s
import Crypto.Noise.Hash.BLAKE2b
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Hash.SHA512
import Crypto.Noise.Types

import HandshakeStates
import Instances()

is25519 :: KeyPair Curve25519
is25519 = curveBytesToPair . bsToSB' $ "I\f\232\218A\210\230\147\FS\222\167\v}l\243!\168.\ESC\t\SYN\"\169\179A`\DC28\211\169tC"

rs25519 :: KeyPair Curve25519
rs25519 = curveBytesToPair . bsToSB' $ "\ETB\157\&7\DC2\252\NUL\148\172\148\133\218\207\&8\221y\144\209\168FX\224Ser_\178|\153.\FSg&"

re25519 :: KeyPair Curve25519
re25519 = curveBytesToPair . bsToSB' $ "<\231\151\151\180\217\146\DLEI}\160N\163iKc\162\210Y\168R\213\206&gm\169r\SUB[\\'"

w :: Chan ByteString -> ByteString -> IO ()
w chan msg = do
  writeChan chan msg
  threadDelay 1000

r :: Chan ByteString -> IO ByteString
r chan = do
  threadDelay 1000
  readChan chan

handshakeBench :: (Cipher c, Curve d, Hash h)
               => HandshakeState c d h
               -> HandshakeState c d h
               -> IO (Plaintext, Plaintext)
handshakeBench ihs rhs = do
  chan <- newChan
  let hc = HandshakeCallbacks (w chan) (r chan) (\_ -> return ()) (return "")
  ((csAlice1, csAlice2), (csBob1, csBob2)) <- concurrently (runHandshake ihs hc) (runHandshake rhs hc)

  let x = decrypt csBob2 . encrypt csAlice1 $ ""
      y = decrypt csAlice2 . encrypt csBob1 $ ""

  return $!! (x, y)

  where
    encrypt cs p = fst $ encryptPayload p cs
    decrypt cs ct = fst $ decryptPayload ct cs

mkHandshakes :: forall c d h proxy. (Cipher c, Curve d, Hash h)
             => HandshakeKeys d
             -> proxy (c, h)
             -> [Benchmark]
mkHandshakes hks _ =
  let nni, nnr, kni, knr, nki, nkr, kki, kkr, nei, ner, kei, ker, nxi, nxr,
        kxi, kxr, xni, xnr, ini, inr, xki, xkr, iki, ikr, xei, xer, iei, ier,
        xxi, xxr, ixi, ixr, xri, xrr, ni, nr, ki, kr, xi, xr
        :: HandshakeState c d h
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
      xri = noiseXRIHS hks
      xrr = noiseXRRHS hks
      ni  = noiseNIHS  hks
      nr  = noiseNRHS  hks
      ki  = noiseKIHS  hks
      kr  = noiseKRHS  hks
      xi  = noiseXIHS  hks
      xr  = noiseXRHS  hks in
  [ bench "NoisePSK_NN" $ whnfIO (handshakeBench nni nnr)
  , bench "NoisePSK_KN" $ whnfIO (handshakeBench kni knr)
  , bench "NoisePSK_NK" $ whnfIO (handshakeBench nki nkr)
  , bench "NoisePSK_KK" $ whnfIO (handshakeBench kki kkr)
  , bench "NoisePSK_NE" $ whnfIO (handshakeBench nei ner)
  , bench "NoisePSK_KE" $ whnfIO (handshakeBench kei ker)
  , bench "NoisePSK_NX" $ whnfIO (handshakeBench nxi nxr)
  , bench "NoisePSK_KX" $ whnfIO (handshakeBench kxi kxr)
  , bench "NoisePSK_XN" $ whnfIO (handshakeBench xni xnr)
  , bench "NoisePSK_IN" $ whnfIO (handshakeBench ini inr)
  , bench "NoisePSK_XK" $ whnfIO (handshakeBench xki xkr)
  , bench "NoisePSK_IK" $ whnfIO (handshakeBench iki ikr)
  , bench "NoisePSK_XE" $ whnfIO (handshakeBench xei xer)
  , bench "NoisePSK_IE" $ whnfIO (handshakeBench iei ier)
  , bench "NoisePSK_XX" $ whnfIO (handshakeBench xxi xxr)
  , bench "NoisePSK_IX" $ whnfIO (handshakeBench ixi ixr)
  , bench "NoisePSK_XR" $ whnfIO (handshakeBench xri xrr)
  , bench "NoisePSK_N"  $ whnfIO (handshakeBench ni  nr )
  , bench "NoisePSK_K"  $ whnfIO (handshakeBench ki  kr )
  , bench "NoisePSK_X"  $ whnfIO (handshakeBench xi  xr )
  ]

main :: IO ()
main =
  let hks = HandshakeKeys (Just "cacophony") is25519 rs25519 re25519 in
  defaultMain
  [ bgroup "Curve25519-ChaChaPoly1305-SHA256"
    (mkHandshakes hks (Proxy :: Proxy (ChaChaPoly1305, SHA256)))
  , bgroup "Curve25519-ChaChaPoly1305-SHA512"
    (mkHandshakes hks (Proxy :: Proxy (ChaChaPoly1305, SHA512)))
  , bgroup "Curve25519-ChaChaPoly1305-BLAKE2s"
    (mkHandshakes hks (Proxy :: Proxy (ChaChaPoly1305, BLAKE2s)))
  , bgroup "Curve25519-ChaChaPoly1305-BLAKE2b"
    (mkHandshakes hks (Proxy :: Proxy (ChaChaPoly1305, BLAKE2b)))
  , bgroup "Curve25519-AESGCM-SHA256"
    (mkHandshakes hks (Proxy :: Proxy (AESGCM, SHA256)))
  , bgroup "Curve25519-AESGCM-SHA512"
    (mkHandshakes hks (Proxy :: Proxy (AESGCM, SHA512)))
  , bgroup "Curve25519-AESGCM-BLAKE2s"
    (mkHandshakes hks (Proxy :: Proxy (AESGCM, BLAKE2s)))
  , bgroup "Curve25519-AESGCM-BLAKE2b"
    (mkHandshakes hks (Proxy :: Proxy (AESGCM, BLAKE2b)))
  ]
