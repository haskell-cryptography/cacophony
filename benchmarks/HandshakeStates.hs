{-# LANGUAGE OverloadedStrings, RecordWildCards #-}
module HandshakeStates where

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Handshake
import Crypto.Noise.HandshakePatterns
import Crypto.Noise.Hash

data HandshakeKeys d =
  HandshakeKeys { psk           :: Maybe Plaintext
                , initStatic    :: KeyPair d
                , respStatic    :: KeyPair d
                , respEphemeral :: KeyPair d
                }

noiseNNIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNNIHS HandshakeKeys{..} =
  handshakeState
  noiseNNI
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing

noiseKNIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKNIHS HandshakeKeys{..} =
  handshakeState
  noiseKNI
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseNKIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNKIHS HandshakeKeys{..} =
  handshakeState
  noiseNKI
  ""
  psk
  Nothing
  Nothing
  (Just (snd respStatic))
  Nothing

noiseKKIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKKIHS HandshakeKeys{..} =
  handshakeState
  noiseKKI
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseNEIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNEIHS HandshakeKeys{..} =
  handshakeState
  noiseNEI
  ""
  psk
  Nothing
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))

noiseKEIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKEIHS HandshakeKeys{..} =
  handshakeState
  noiseKEI
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))

noiseNXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNXIHS HandshakeKeys{..} =
  handshakeState
  noiseNXI
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing

noiseKXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKXIHS HandshakeKeys{..} =
  handshakeState
  noiseKXI
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseXNIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXNIHS HandshakeKeys{..} =
  handshakeState
  noiseXNI
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseINIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseINIHS HandshakeKeys{..} =
  handshakeState
  noiseINI
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseXKIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXKIHS HandshakeKeys{..} =
  handshakeState
  noiseXKI
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseIKIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIKIHS HandshakeKeys{..} =
  handshakeState
  noiseIKI
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseXEIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXEIHS HandshakeKeys{..} =
  handshakeState
  noiseXEI
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))

noiseIEIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIEIHS HandshakeKeys{..} =
  handshakeState
  noiseIEI
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))

noiseXXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXXIHS HandshakeKeys{..} =
  handshakeState
  noiseXXI
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseIXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIXIHS HandshakeKeys{..} =
  handshakeState
  noiseIXI
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseNIHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseNIHS HandshakeKeys{..} =
  handshakeState
  noiseNI
  ""
  psk
  Nothing
  Nothing
  (Just (snd respStatic))
  Nothing

noiseKIHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseKIHS HandshakeKeys{..} =
  handshakeState
  noiseKI
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXIHS HandshakeKeys{..} =
  handshakeState
  noiseXI
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseNNRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNNRHS HandshakeKeys{..} =
  handshakeState
  noiseNNR
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing

noiseKNRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKNRHS HandshakeKeys{..} =
  handshakeState
  noiseKNR
  ""
  psk
  Nothing
  Nothing
  (Just (snd initStatic))
  Nothing

noiseNKRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNKRHS HandshakeKeys{..} =
  handshakeState
  noiseNKR
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseKKRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKKRHS HandshakeKeys{..} =
  handshakeState
  noiseKKR
  ""
  psk
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing

noiseNERHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNERHS HandshakeKeys{..} =
  handshakeState
  noiseNER
  ""
  psk
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing

noiseKERHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKERHS HandshakeKeys{..} =
  handshakeState
  noiseKER
  ""
  psk
  (Just respStatic)
  (Just respEphemeral)
  (Just (snd initStatic))
  Nothing

noiseNXRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNXRHS HandshakeKeys{..} =
  handshakeState
  noiseNXR
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseKXRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKXRHS HandshakeKeys{..} =
  handshakeState
  noiseKXR
  ""
  psk
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing

noiseXNRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXNRHS HandshakeKeys{..} =
  handshakeState
  noiseXNR
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing

noiseINRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseINRHS HandshakeKeys{..} =
  handshakeState
  noiseINR
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing

noiseXKRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXKRHS HandshakeKeys{..} =
  handshakeState
  noiseXKR
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseIKRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIKRHS HandshakeKeys{..} =
  handshakeState
  noiseIKR
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseXERHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXERHS HandshakeKeys{..} =
  handshakeState
  noiseXER
  ""
  psk
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing

noiseIERHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIERHS HandshakeKeys{..} =
  handshakeState
  noiseIER
  ""
  psk
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing

noiseXXRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXXRHS HandshakeKeys{..} =
  handshakeState
  noiseXXR
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseIXRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIXRHS HandshakeKeys{..} =
  handshakeState
  noiseIXR
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseNRHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseNRHS HandshakeKeys{..} =
  handshakeState
  noiseNR
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseKRHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseKRHS HandshakeKeys{..} =
  handshakeState
  noiseKR
  ""
  psk
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing

noiseXRHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseXRHS HandshakeKeys{..} =
  handshakeState
  noiseXR
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
