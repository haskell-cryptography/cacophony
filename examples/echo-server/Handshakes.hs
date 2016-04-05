{-# LANGUAGE RecordWildCards #-}
module Handshakes where

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Hash
import Crypto.Noise.Handshake
import Crypto.Noise.HandshakePatterns
import Crypto.Noise.Types

import Types

data HandshakeKeys d =
  HandshakeKeys { hkPrologue     :: Plaintext
                , hkPSK          :: Maybe Plaintext
                , hkLocalStatic  :: KeyPair d
                , hkRemoteStatic :: PublicKey d
                }

mkHandshake :: (Cipher c, Curve d, Hash h)
            => HandshakeKeys d
            -> HandshakeType
            -> CipherType c
            -> HashType h
            -> HandshakeState c d h
mkHandshake HandshakeKeys{..} NoiseNN _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseNN
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Nothing
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Nothing
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }

mkHandshake HandshakeKeys{..} NoiseKN _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseKN
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Nothing
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Just hkRemoteStatic
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }

mkHandshake HandshakeKeys{..} NoiseNK _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseNK
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Just hkLocalStatic
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Nothing
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }

mkHandshake HandshakeKeys{..} NoiseKK _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseKK
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Just hkLocalStatic
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Just hkRemoteStatic
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }

mkHandshake HandshakeKeys{..} NoiseNX _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseNX
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Just hkLocalStatic
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Nothing
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }

mkHandshake HandshakeKeys{..} NoiseKX _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseKX
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Just hkLocalStatic
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Just hkRemoteStatic
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }

mkHandshake HandshakeKeys{..} NoiseXN _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseXN
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Nothing
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Nothing
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }

mkHandshake HandshakeKeys{..} NoiseIN _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseIN
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Nothing
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Nothing
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }

mkHandshake HandshakeKeys{..} NoiseXK _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseXK
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Just hkLocalStatic
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Nothing
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }

mkHandshake HandshakeKeys{..} NoiseIK _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseIK
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Just hkLocalStatic
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Nothing
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }

mkHandshake HandshakeKeys{..} NoiseXX _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseXX
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Just hkLocalStatic
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Nothing
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }

mkHandshake HandshakeKeys{..} NoiseIX _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseIX
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Just hkLocalStatic
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Nothing
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }

mkHandshake HandshakeKeys{..} NoiseXR _ _ = handshakeState
  HandshakeStateParams { hspPattern            = noiseXR
                       , hspPrologue           = hkPrologue
                       , hspPreSharedKey       = hkPSK
                       , hspLocalStaticKey     = Just hkLocalStatic
                       , hspLocalEphemeralKey  = Nothing
                       , hspRemoteStaticKey    = Nothing
                       , hspRemoteEphemeralKey = Nothing
                       , hspInitiator          = False
                       }
