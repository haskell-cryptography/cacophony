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
  noiseNNI
  ""
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
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
  (Just "cacophony")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
