{-# LANGUAGE OverloadedStrings, RecordWildCards #-}
module HandshakeStates where

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
noiseNNIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseNNRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseKNIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseKNRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseNKIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseNKRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseKKIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseKKRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseNEIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseNERHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseKEIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseKERHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseNXIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseNXRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseKXIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseKXRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseXNIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseXNRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseINIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseINRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseXKIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseXKRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseIKIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseIKRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseXEIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseXERHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseIEIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseIERHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseXXIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseXXRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseIXIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseIXRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseXRIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseXRRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseNIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseNRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseKIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseKRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseXIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
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
noiseXRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
  noiseX
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False
