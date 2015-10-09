{-# LANGUAGE OverloadedStrings #-}
module Handshake where

import Imports

import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.HandshakeState
import Crypto.Noise.Internal.Descriptor
import Crypto.Noise.Types
import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve.Curve25519

import Data.ByteString (ByteString)

hsn :: ScrubbedBytes
hsn = convert ("Noise_NN" :: ByteString)

aliceHS, bobHS :: HandshakeState ChaChaPoly1305 Curve25519
aliceHS = handshakeState hsn Nothing Nothing Nothing Nothing
bobHS = handshakeState hsn Nothing Nothing Nothing Nothing

doNN :: IO Bool
doNN = do
  (aliceToBob1, aliceHS') <- writeHandshakeMsg aliceHS noiseNNI1 $ Plaintext $ convert ("" :: ByteString)
  let (_, bobHS') = readHandshakeMsg bobHS aliceToBob1 noiseNNR1
  (bobToAlice1, csBob1, csBob2) <- writeHandshakeMsgFinal bobHS' noiseNNR2 $ Plaintext $ convert ("" :: ByteString)
  let (_, csAlice1, csAlice2) = readHandshakeMsgFinal aliceHS' bobToAlice1 noiseNNI2
  return $ csk csAlice1 == csk csBob1 && csk csAlice2 == csk csBob2

tests :: TestTree
tests = testGroup "Handshakes"
  [ testProperty "Noise_NN" $ ioProperty doNN
  ]
