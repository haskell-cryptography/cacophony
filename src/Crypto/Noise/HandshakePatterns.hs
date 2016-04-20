{-# LANGUAGE OverloadedStrings #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.HandshakePatterns
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
--
-- This module contains all of the handshake patterns specified in sections
-- 8.2 and 8.3 as well as unspecified patterns found in previous drafts of
-- the protocol.

module Crypto.Noise.HandshakePatterns
  ( -- * Types
    HandshakePattern
    -- * Functions
  , noiseNN
  , noiseKN
  , noiseNK
  , noiseKK
  , noiseNE
  , noiseKE
  , noiseNX
  , noiseKX
  , noiseXN
  , noiseIN
  , noiseXK
  , noiseIK
  , noiseXE
  , noiseIE
  , noiseXX
  , noiseIX
  , noiseXR
  , noiseN
  , noiseK
  , noiseX
  ) where

import Crypto.Noise.Internal.HandshakePattern

-- | @Noise_NN():
--  -> e
--  <- e, dhee@
noiseNN :: HandshakePattern
noiseNN = HandshakePattern "NN" $ do
  initiator e

  responder $ do
    e
    dhee

-- | @Noise_KN(s):
--  -> s
--  ...
--  -> e
--  <- e, dhee, dhes@
noiseKN :: HandshakePattern
noiseKN = HandshakePattern "KN" $ do
  preInitiator s

  initiator e

  responder $ do
    e
    dhee
    dhes

-- | @Noise_NK(rs):
--  <- s
--  ...
--  -> e, dhes
--  <- e, dhee@
noiseNK :: HandshakePattern
noiseNK = HandshakePattern "NK" $ do
  preResponder s

  initiator $ do
    e
    dhes

  responder $ do
    e
    dhee

-- | @Noise_KK(s, rs):
--  -> s
--  <- s
--  ...
--  -> e, dhes, dhss
--  <- e, dhee, dhes@
noiseKK :: HandshakePattern
noiseKK = HandshakePattern "KK" $ do
  preInitiator s

  preResponder s

  initiator $ do
    e
    dhes
    dhss

  responder $ do
    e
    dhee
    dhes

-- | @Noise_NE(rs, re):
--  <- s, e
--  ...
--  -> e, dhee, dhes
--  <- e, dhee@
--
--  This is not an officially recognized pattern (see section 8.6).
noiseNE :: HandshakePattern
noiseNE = HandshakePattern "NE" $ do
  preResponder $ do
    s
    e

  initiator $ do
    e
    dhee
    dhes

  responder $ do
    e
    dhee

-- | @Noise_KE(s, rs, re):
--  -> s
--  <- s, e
--  ...
--  -> e, dhee, dhes, dhse
--  <- e, dhee, dhes@
--
--  This is not an officially recognized pattern (see section 8.6).
noiseKE :: HandshakePattern
noiseKE = HandshakePattern "KE" $ do
  preInitiator s

  preResponder $ do
    s
    e

  initiator $ do
    e
    dhee
    dhes
    dhse

  responder $ do
    e
    dhee
    dhes

-- | @Noise_NX(rs):
--  -> e
--  <- e, dhee, s, dhse@
noiseNX :: HandshakePattern
noiseNX = HandshakePattern "NX" $ do
  initiator e

  responder $ do
    e
    dhee
    s
    dhse

-- | @Noise_KX(s, rs):
--  -> s
--  ...
--  -> e
--  <- e, dhee, dhes, s, dhse@
noiseKX :: HandshakePattern
noiseKX = HandshakePattern "KX" $ do
  preInitiator s

  initiator e

  responder $ do
    e
    dhee
    dhes
    s
    dhse

-- | @Noise_XN(s):
--  -> e
--  <- e, dhee
--  -> s, dhse@
noiseXN :: HandshakePattern
noiseXN = HandshakePattern "XN" $ do
  initiator e

  responder $ do
    e
    dhee

  initiator $ do
    s
    dhse

-- | @Noise_IN(s):
--  -> e, s
--  <- e, dhee, dhes@
noiseIN :: HandshakePattern
noiseIN = HandshakePattern "IN" $ do
  initiator $ do
    e
    s

  responder $ do
    e
    dhee
    dhes

-- | @Noise_XK(s, rs):
--  <- s
--  ...
--  -> e, dhes
--  <- e, dhee
--  -> s, dhse@
noiseXK :: HandshakePattern
noiseXK = HandshakePattern "XK" $ do
  preResponder s

  initiator $ do
    e
    dhes

  responder $ do
    e
    dhee

  initiator $ do
    s
    dhse

-- | @Noise_IK(s, rs):
--  <- s
--  ...
--  -> e, dhes, s, dhss
--  <- e, dhee, dhes@
noiseIK :: HandshakePattern
noiseIK = HandshakePattern "IK" $ do
  preResponder s

  initiator $ do
    e
    dhes
    s
    dhss

  responder $ do
    e
    dhee
    dhes

-- | @Noise_XE(s, rs, re):
--  <- s, e
--  ...
--  -> e, dhee, dhes
--  <- e, dhee
--  -> s, dhse@
--
--  This is not an officially recognized pattern (see section 8.6).
noiseXE :: HandshakePattern
noiseXE = HandshakePattern "XE" $ do
  preResponder $ do
    s
    e

  initiator $ do
    e
    dhee
    dhes

  responder $ do
    e
    dhee

  initiator $ do
    s
    dhse

-- | @Noise_IE(s, rs, re):
--  <- s, e
--  ...
--  -> e, dhee, dhes, s, dhse
--  <- e, dhee, dhes@
--
--  This is not an officially recognized pattern (see section 8.6).
noiseIE :: HandshakePattern
noiseIE = HandshakePattern "IE" $ do
  preResponder $ do
    s
    e

  initiator $ do
    e
    dhee
    dhes
    s
    dhse

  responder $ do
    e
    dhee
    dhes

-- | @Noise_XX(s, rs):
--  -> e
--  <- e, dhee, s, dhse
--  -> s, dhse@
noiseXX :: HandshakePattern
noiseXX = HandshakePattern "XX" $ do
  initiator e

  responder $ do
    e
    dhee
    s
    dhse

  initiator $ do
    s
    dhse

-- | @Noise_IX(s, rs):
--  -> e, s
--  <- e, dhee, dhes, s, dhse@
noiseIX :: HandshakePattern
noiseIX = HandshakePattern "IX" $ do
  initiator $ do
    e
    s

  responder $ do
    e
    dhee
    dhes
    s
    dhse

-- | @Noise_XR(s, rs):
--  -> e
--  <- e, dhee
--  -> s, dhse
--  <- s, dhse@
noiseXR :: HandshakePattern
noiseXR = HandshakePattern "XR" $ do
  initiator e

  responder $ do
    e
    dhee

  initiator $ do
    s
    dhse

  responder $ do
    s
    dhse

-- | @Noise_N(rs):
--  <- s
--  ...
--  -> e, dhes@
noiseN :: HandshakePattern
noiseN = HandshakePattern "N" $ do
  preResponder s

  initiator $ do
    e
    dhes

-- | @Noise_K(s, rs):
--  -> s
--  <- s
--  ...
--  -> e, dhes, dhss@
noiseK :: HandshakePattern
noiseK = HandshakePattern "K" $ do
  preInitiator s

  preResponder s

  initiator $ do
    e
    dhes
    dhss

-- | @Noise_X(s, rs):
--  <- s
--  ...
--  -> e, dhes, s, dhss@
noiseX :: HandshakePattern
noiseX = HandshakePattern "X" $ do
  preResponder s

  initiator $ do
    e
    dhes
    s
    dhss
