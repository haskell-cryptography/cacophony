{-# LANGUAGE OverloadedStrings, RecordWildCards #-}
module HandshakeStates where

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Handshake
import Crypto.Noise.HandshakePatterns
import Crypto.Noise.Hash

data HandshakeKeys d =
  HandshakeKeys { initStatic    :: KeyPair d
                , respStatic    :: KeyPair d
                , respEphemeral :: KeyPair d
                }

noiseNNIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNNIHS HandshakeKeys{..} =
  handshakeState
  "NN"
  noiseNNI
  ""
  Nothing
  Nothing
  Nothing
  Nothing

noiseKNIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKNIHS HandshakeKeys{..} =
  handshakeState
  "KN"
  noiseKNI
  ""
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseNKIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNKIHS HandshakeKeys{..} =
  handshakeState
  "NK"
  noiseNKI
  ""
  Nothing
  Nothing
  (Just (snd respStatic))
  Nothing

noiseKKIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKKIHS HandshakeKeys{..} =
  handshakeState
  "KK"
  noiseKKI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseNEIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNEIHS HandshakeKeys{..} =
  handshakeState
  "NE"
  noiseNEI
  ""
  Nothing
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))

noiseKEIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKEIHS HandshakeKeys{..} =
  handshakeState
  "KE"
  noiseKEI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))

noiseNXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNXIHS HandshakeKeys{..} =
  handshakeState
  "NX"
  noiseNXI
  ""
  Nothing
  Nothing
  Nothing
  Nothing

noiseKXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKXIHS HandshakeKeys{..} =
  handshakeState
  "KX"
  noiseKXI
  ""
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseXNIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXNIHS HandshakeKeys{..} =
  handshakeState
  "XN"
  noiseXNI
  ""
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseINIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseINIHS HandshakeKeys{..} =
  handshakeState
  "IN"
  noiseINI
  ""
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseXKIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXKIHS HandshakeKeys{..} =
  handshakeState
  "XK"
  noiseXKI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseIKIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIKIHS HandshakeKeys{..} =
  handshakeState
  "IK"
  noiseIKI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseXEIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXEIHS HandshakeKeys{..} =
  handshakeState
  "XE"
  noiseXEI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))

noiseIEIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIEIHS HandshakeKeys{..} =
  handshakeState
  "IE"
  noiseIEI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))

noiseXXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXXIHS HandshakeKeys{..} =
  handshakeState
  "XX"
  noiseXXI
  ""
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseIXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIXIHS HandshakeKeys{..} =
  handshakeState
  "IX"
  noiseIXI
  ""
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseNIHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseNIHS HandshakeKeys{..} =
  handshakeState
  "N"
  noiseNI
  ""
  Nothing
  Nothing
  (Just (snd respStatic))
  Nothing

noiseKIHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseKIHS HandshakeKeys{..} =
  handshakeState
  "K"
  noiseKI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXIHS HandshakeKeys{..} =
  handshakeState
  "X"
  noiseXI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseNNRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNNRHS HandshakeKeys{..} =
  handshakeState
  "NN"
  noiseNNR
  ""
  Nothing
  Nothing
  Nothing
  Nothing

noiseKNRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKNRHS HandshakeKeys{..} =
  handshakeState
  "KN"
  noiseKNR
  ""
  Nothing
  Nothing
  (Just (snd initStatic))
  Nothing

noiseNKRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNKRHS HandshakeKeys{..} =
  handshakeState
  "NK"
  noiseNKR
  ""
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseKKRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKKRHS HandshakeKeys{..} =
  handshakeState
  "KK"
  noiseKKR
  ""
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing

noiseNERHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNERHS HandshakeKeys{..} =
  handshakeState
  "NE"
  noiseNER
  ""
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing

noiseKERHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKERHS HandshakeKeys{..} =
  handshakeState
  "KE"
  noiseKER
  ""
  (Just respStatic)
  (Just respEphemeral)
  (Just (snd initStatic))
  Nothing

noiseNXRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNXRHS HandshakeKeys{..} =
  handshakeState
  "NX"
  noiseNXR
  ""
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseKXRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKXRHS HandshakeKeys{..} =
  handshakeState
  "KX"
  noiseKXR
  ""
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing

noiseXNRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXNRHS HandshakeKeys{..} =
  handshakeState
  "XN"
  noiseXNR
  ""
  Nothing
  Nothing
  Nothing
  Nothing

noiseINRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseINRHS HandshakeKeys{..} =
  handshakeState
  "IN"
  noiseINR
  ""
  Nothing
  Nothing
  Nothing
  Nothing

noiseXKRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXKRHS HandshakeKeys{..} =
  handshakeState
  "XK"
  noiseXKR
  ""
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseIKRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIKRHS HandshakeKeys{..} =
  handshakeState
  "IK"
  noiseIKR
  ""
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseXERHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXERHS HandshakeKeys{..} =
  handshakeState
  "XE"
  noiseXER
  ""
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing

noiseIERHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIERHS HandshakeKeys{..} =
  handshakeState
  "IE"
  noiseIER
  ""
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing

noiseXXRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXXRHS HandshakeKeys{..} =
  handshakeState
  "XX"
  noiseXXR
  ""
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseIXRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIXRHS HandshakeKeys{..} =
  handshakeState
  "IX"
  noiseIXR
  ""
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseNRHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseNRHS HandshakeKeys{..} =
  handshakeState
  "N"
  noiseNR
  ""
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseKRHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseKRHS HandshakeKeys{..} =
  handshakeState
  "K"
  noiseKR
  ""
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing

noiseXRHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseXRHS HandshakeKeys{..} =
  handshakeState
  "X"
  noiseXR
  ""
  (Just respStatic)
  Nothing
  Nothing
  Nothing
