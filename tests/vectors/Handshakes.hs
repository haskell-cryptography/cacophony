{-# LANGUAGE RecordWildCards, ScopedTypeVariables #-}
module Handshakes where

import Control.Lens

import Crypto.Noise
import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash
import Crypto.Noise.HandshakePatterns

import Types

data HandshakeKeys d =
  HandshakeKeys { hkPrologue       :: Plaintext
                , hkPSK            :: Maybe Plaintext
                , hkLocalStatic    :: KeyPair d
                , hkLocalEphemeral :: KeyPair d
                , hkRemoteStatic   :: PublicKey d
                }

mkNoiseState :: forall c d h. (Cipher c, DH d, Hash h)
             => HandshakeKeys d
             -> HandshakeType
             -> HandshakeRole
             -> CipherType c
             -> HashType h
             -> NoiseState c d h
mkNoiseState HandshakeKeys{..} NoiseNN r _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseNN r :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseKN InitiatorRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseKN InitiatorRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseKN ResponderRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseKN ResponderRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoRemoteStatic   .~ Just hkRemoteStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseNK InitiatorRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseNK InitiatorRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoRemoteStatic   .~ Just hkRemoteStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseNK ResponderRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseNK ResponderRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseKK r _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseKK r :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoRemoteStatic   .~ Just hkRemoteStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseNX InitiatorRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseNX InitiatorRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseNX ResponderRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseNX ResponderRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseKX InitiatorRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseKX InitiatorRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseKX ResponderRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseKX ResponderRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoRemoteStatic   .~ Just hkRemoteStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseXN InitiatorRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseXN InitiatorRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseXN ResponderRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseXN ResponderRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseIN InitiatorRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseIN InitiatorRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseIN ResponderRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseIN ResponderRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseXK InitiatorRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseXK InitiatorRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoRemoteStatic   .~ Just hkRemoteStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseXK ResponderRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseXK ResponderRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseIK InitiatorRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseIK InitiatorRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoRemoteStatic   .~ Just hkRemoteStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseIK ResponderRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseIK ResponderRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseXX r _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseXX r :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseIX r _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseIX r :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseXR r _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseXR r :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseN InitiatorRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseN InitiatorRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoRemoteStatic   .~ Just hkRemoteStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseN ResponderRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseN ResponderRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseK r _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseK r :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoRemoteStatic   .~ Just hkRemoteStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseX InitiatorRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseX InitiatorRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoRemoteStatic   .~ Just hkRemoteStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral

mkNoiseState HandshakeKeys{..} NoiseX ResponderRole _ _ = noiseState ho
  where
    dho = defaultHandshakeOpts noiseX ResponderRole :: HandshakeOpts d
    ho  = dho & hoPrologue       .~ hkPrologue
              & hoPreSharedKey   .~ hkPSK
              & hoLocalStatic    .~ Just hkLocalStatic
              & hoLocalEphemeral .~ Just hkLocalEphemeral
