{-# LANGUAGE OverloadedStrings, RecordWildCards #-}
module Handshakes where

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Handshake
import Crypto.Noise.HandshakePatterns
import Crypto.Noise.Hash
import Crypto.Noise.Types (Plaintext(..))

data HandshakeKeys d =
  HandshakeKeys { psk           :: Maybe Plaintext
                , initStatic    :: KeyPair d
                , respStatic    :: KeyPair d
                , respEphemeral :: KeyPair d
                }

noiseNNIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNNIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseNN
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing
  True

noiseNNRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNNRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseNN
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing
  False

noiseKNIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKNIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseKN
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True

noiseKNRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKNRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseKN
  ""
  psk
  Nothing
  Nothing
  (Just (snd initStatic))
  Nothing
  False

noiseNKIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNKIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseNK
  ""
  psk
  Nothing
  Nothing
  (Just (snd respStatic))
  Nothing
  True

noiseNKRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNKRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseNK
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseKKIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKKIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseKK
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  True

noiseKKRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKKRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseKK
  ""
  psk
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing
  False

noiseNEIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNEIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseNE
  ""
  psk
  Nothing
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  True

noiseNERHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNERHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseNE
  ""
  psk
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  False

noiseKEIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKEIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseKE
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  True

noiseKERHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKERHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseKE
  ""
  psk
  (Just respStatic)
  (Just respEphemeral)
  (Just (snd initStatic))
  Nothing
  False

noiseNXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNXIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseNX
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing
  True

noiseNXRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseNXRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseNX
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseKXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKXIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseKX
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True

noiseKXRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseKXRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseKX
  ""
  psk
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing
  False

noiseXNIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXNIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseXN
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True

noiseXNRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXNRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseXN
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing
  False

noiseINIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseINIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseIN
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True

noiseINRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseINRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseIN
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing
  False

noiseXKIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXKIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseXK
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  True

noiseXKRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXKRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseXK
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseIKIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIKIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseIK
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  True

noiseIKRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIKRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseIK
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseXEIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXEIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseXE
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  True

noiseXERHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXERHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseXE
  ""
  psk
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  False

noiseIEIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIEIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseIE
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  True

noiseIERHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIERHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseIE
  ""
  psk
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  False

noiseXXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXXIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseXX
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True

noiseXXRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXXRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseXX
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseIXIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIXIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseIX
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True

noiseIXRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseIXRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseIX
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseXRIHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXRIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseXR
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True

noiseXRRHS :: (Cipher c, Curve d, Hash h)
           => HandshakeKeys d
           -> HandshakeState c d h
noiseXRRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseXR
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseNIHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseNIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseN
  ""
  psk
  Nothing
  Nothing
  (Just (snd respStatic))
  Nothing
  True

noiseNRHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseNRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseN
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseKIHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseKIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseK
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  True

noiseKRHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseKRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseK
  ""
  psk
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing
  False

noiseXIHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseXIHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseX
  ""
  psk
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  True

noiseXRHS :: (Cipher c, Curve d, Hash h)
          => HandshakeKeys d
          -> HandshakeState c d h
noiseXRHS HandshakeKeys{..} = handshakeState $ HandshakeOpts
  noiseX
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False
