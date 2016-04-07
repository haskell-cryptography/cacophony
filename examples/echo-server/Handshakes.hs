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
  HandshakeOpts { hoPattern            = noiseNN
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Nothing
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Nothing
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }

mkHandshake HandshakeKeys{..} NoiseKN _ _ = handshakeState
  HandshakeOpts { hoPattern            = noiseKN
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Nothing
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Just hkRemoteStatic
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }

mkHandshake HandshakeKeys{..} NoiseNK _ _ = handshakeState
  HandshakeOpts { hoPattern            = noiseNK
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Just hkLocalStatic
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Nothing
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }

mkHandshake HandshakeKeys{..} NoiseKK _ _ = handshakeState
  HandshakeOpts { hoPattern            = noiseKK
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Just hkLocalStatic
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Just hkRemoteStatic
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }

mkHandshake HandshakeKeys{..} NoiseNX _ _ = handshakeState
  HandshakeOpts { hoPattern            = noiseNX
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Just hkLocalStatic
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Nothing
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }

mkHandshake HandshakeKeys{..} NoiseKX _ _ = handshakeState
  HandshakeOpts { hoPattern            = noiseKX
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Just hkLocalStatic
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Just hkRemoteStatic
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }

mkHandshake HandshakeKeys{..} NoiseXN _ _ = handshakeState
  HandshakeOpts { hoPattern            = noiseXN
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Nothing
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Nothing
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }

mkHandshake HandshakeKeys{..} NoiseIN _ _ = handshakeState
  HandshakeOpts { hoPattern            = noiseIN
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Nothing
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Nothing
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }

mkHandshake HandshakeKeys{..} NoiseXK _ _ = handshakeState
  HandshakeOpts { hoPattern            = noiseXK
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Just hkLocalStatic
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Nothing
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }

mkHandshake HandshakeKeys{..} NoiseIK _ _ = handshakeState
  HandshakeOpts { hoPattern            = noiseIK
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Just hkLocalStatic
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Nothing
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }

mkHandshake HandshakeKeys{..} NoiseXX _ _ = handshakeState
  HandshakeOpts { hoPattern            = noiseXX
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Just hkLocalStatic
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Nothing
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }

mkHandshake HandshakeKeys{..} NoiseIX _ _ = handshakeState
  HandshakeOpts { hoPattern            = noiseIX
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Just hkLocalStatic
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Nothing
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }

mkHandshake HandshakeKeys{..} NoiseXR _ _ = handshakeState
  HandshakeOpts { hoPattern            = noiseXR
                , hoPrologue           = hkPrologue
                , hoPreSharedKey       = hkPSK
                , hoLocalStaticKey     = Just hkLocalStatic
                , hoLocalEphemeralKey  = Nothing
                , hoRemoteStaticKey    = Nothing
                , hoRemoteEphemeralKey = Nothing
                , hoInitiator          = False
                }
