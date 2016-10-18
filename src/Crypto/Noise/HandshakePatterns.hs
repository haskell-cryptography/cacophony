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
  , noiseNX
  , noiseKX
  , noiseXN
  , noiseIN
  , noiseXK
  , noiseIK
  , noiseXX
  , noiseIX
  , noiseN
  , noiseK
  , noiseX
  , noiseXXfallback
  ) where

import Crypto.Noise.Internal.HandshakePattern

-- | @Noise_NN():
--  -> e
--  <- e, ee@
noiseNN :: HandshakePattern
noiseNN = HandshakePattern "NN" $ do
  initiator e

  responder $ do
    e
    ee

-- | @Noise_KN(s):
--  -> s
--  ...
--  -> e
--  <- e, ee, se@
noiseKN :: HandshakePattern
noiseKN = HandshakePattern "KN" $ do
  preInitiator s

  initiator e

  responder $ do
    e
    ee
    se

-- | @Noise_NK(rs):
--  <- s
--  ...
--  -> e, es
--  <- e, ee@
noiseNK :: HandshakePattern
noiseNK = HandshakePattern "NK" $ do
  preResponder s

  initiator $ do
    e
    es

  responder $ do
    e
    ee

-- | @Noise_KK(s, rs):
--  -> s
--  <- s
--  ...
--  -> e, es, ss
--  <- e, ee, se@
noiseKK :: HandshakePattern
noiseKK = HandshakePattern "KK" $ do
  preInitiator s

  preResponder s

  initiator $ do
    e
    es
    ss

  responder $ do
    e
    ee
    se

-- | @Noise_NX(rs):
--  -> e
--  <- e, ee, s, es@
noiseNX :: HandshakePattern
noiseNX = HandshakePattern "NX" $ do
  initiator e

  responder $ do
    e
    ee
    s
    es

-- | @Noise_KX(s, rs):
--  -> s
--  ...
--  -> e
--  <- e, ee, se, s, es@
noiseKX :: HandshakePattern
noiseKX = HandshakePattern "KX" $ do
  preInitiator s

  initiator e

  responder $ do
    e
    ee
    se
    s
    es

-- | @Noise_XN(s):
--  -> e
--  <- e, ee
--  -> s, se@
noiseXN :: HandshakePattern
noiseXN = HandshakePattern "XN" $ do
  initiator e

  responder $ do
    e
    ee

  initiator $ do
    s
    se

-- | @Noise_IN(s):
--  -> e, s
--  <- e, ee, se@
noiseIN :: HandshakePattern
noiseIN = HandshakePattern "IN" $ do
  initiator $ do
    e
    s

  responder $ do
    e
    ee
    se

-- | @Noise_XK(s, rs):
--  <- s
--  ...
--  -> e, es
--  <- e, ee
--  -> s, se@
noiseXK :: HandshakePattern
noiseXK = HandshakePattern "XK" $ do
  preResponder s

  initiator $ do
    e
    es

  responder $ do
    e
    ee

  initiator $ do
    s
    se

-- | @Noise_IK(s, rs):
--  <- s
--  ...
--  -> e, es, s, ss
--  <- e, ee, se@
noiseIK :: HandshakePattern
noiseIK = HandshakePattern "IK" $ do
  preResponder s

  initiator $ do
    e
    es
    s
    ss

  responder $ do
    e
    ee
    se

-- | @Noise_XX(s, rs):
--  -> e
--  <- e, ee, s, es
--  -> s, se@
noiseXX :: HandshakePattern
noiseXX = HandshakePattern "XX" $ do
  initiator e

  responder $ do
    e
    ee
    s
    es

  initiator $ do
    s
    se

-- | @Noise_IX(s, rs):
--  -> e, s
--  <- e, ee, se, s, es@
noiseIX :: HandshakePattern
noiseIX = HandshakePattern "IX" $ do
  initiator $ do
    e
    s

  responder $ do
    e
    ee
    se
    s
    es

-- | @Noise_N(rs):
--  <- s
--  ...
--  -> e, es@
noiseN :: HandshakePattern
noiseN = HandshakePattern "N" $ do
  preResponder s

  initiator $ do
    e
    es

-- | @Noise_K(s, rs):
--  -> s
--  <- s
--  ...
--  -> e, es, ss@
noiseK :: HandshakePattern
noiseK = HandshakePattern "K" $ do
  preInitiator s

  preResponder s

  initiator $ do
    e
    es
    ss

-- | @Noise_X(s, rs):
--  <- s
--  ...
--  -> e, es, s, ss@
noiseX :: HandshakePattern
noiseX = HandshakePattern "X" $ do
  preResponder s

  initiator $ do
    e
    es
    s
    ss

-- | @Noise_XXfallback(s, rs, re):
--  <- e
--  ...
--  -> e, ee, s, se
--  <- s, es
noiseXXfallback :: HandshakePattern
noiseXXfallback = HandshakePattern "XXfallback" $ do
  preResponder e

  initiator $ do
    e
    ee
    s
    se

  responder $ do
    s
    es
