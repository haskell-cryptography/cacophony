{-# LANGUAGE OverloadedStrings #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.HandshakePatterns
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
--
-- This module contains all of the handshake patterns specified in sections
-- 7.2 and 7.3 as well as unspecified patterns found in previous drafts of
-- the protocol spec.

module Crypto.Noise.HandshakePatterns
  ( -- * Functions
    noiseNN
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
noiseNN :: HandshakePattern c
noiseNN = HandshakePattern "NN" Nothing $ do
  initiator e

  responder $ do
    e
    dhee

  split

-- | @Noise_KN(s):
--  -> s
--  ...
--  -> e
--  <- e, dhee, dhes@
noiseKN :: HandshakePattern c
noiseKN = HandshakePattern "KN" (Just pmp) hp
  where
    pmp = initiator s

    hp = do
      initiator e

      responder $ do
        e
        dhee
        dhes

      split

-- | @Noise_NK(rs):
--  <- s
--  ...
--  -> e, dhes
--  <- e, dhee@
noiseNK :: HandshakePattern c
noiseNK = HandshakePattern "NK" (Just pmp) hp
  where
    pmp = responder s

    hp = do
      initiator $ do
        e
        dhes

      responder $ do
        e
        dhee

      split

-- | @Noise_KK(s, rs):
--  -> s
--  <- s
--  ...
--  -> e, dhes, dhss
--  <- e, dhee, dhes@
noiseKK :: HandshakePattern c
noiseKK = HandshakePattern "KK" (Just pmp) hp
  where
    pmp = do
      initiator s

      responder s

    hp = do
      initiator $ do
        e
        dhes
        dhss

      responder $ do
        e
        dhee
        dhes

      split

-- | @Noise_NE(rs, re):
--  <- s, e
--  ...
--  -> e, dhee, dhes
--  <- e, dhee@
noiseNE :: HandshakePattern c
noiseNE = HandshakePattern "NE" (Just pmp) hp
  where
    pmp = responder $ do
      s
      e

    hp = do
      initiator $ do
        e
        dhee
        dhes

      responder $ do
        e
        dhee

      split

-- | @Noise_KE(s, rs, re):
--  -> s
--  <- s, e
--  ...
--  -> e, dhee, dhes, dhse
--  <- e, dhee, dhes@
noiseKE :: HandshakePattern c
noiseKE = HandshakePattern "KE" (Just pmp) hp
  where
    pmp = do
      initiator s

      responder $ do
        s
        e

    hp = do
      initiator $ do
        e
        dhee
        dhes
        dhse

      responder $ do
        e
        dhee
        dhes

      split

-- | @Noise_NX(rs):
--  -> e
--  <- e, dhee, s, dhse@
noiseNX :: HandshakePattern c
noiseNX = HandshakePattern "NX" Nothing $ do
  initiator e

  responder $ do
    e
    dhee
    s
    dhse

  split

-- | @Noise_KX(s, rs):
--  -> s
--  ...
--  -> e
--  <- e, dhee, dhes, s, dhse@
noiseKX :: HandshakePattern c
noiseKX = HandshakePattern "KX" (Just pmp) hp
  where
    pmp = initiator s

    hp = do
      initiator e

      responder $ do
        e
        dhee
        dhes
        s
        dhse

      split

-- | @Noise_XN(s):
--  -> e
--  <- e, dhee
--  -> s, dhse@
noiseXN :: HandshakePattern c
noiseXN = HandshakePattern "XN" Nothing $ do
  initiator e

  responder $ do
    e
    dhee

  initiator $ do
    s
    dhse

  split

-- | @Noise_IN(s):
--  -> e, s
--  <- e, dhee, dhes@
noiseIN :: HandshakePattern c
noiseIN = HandshakePattern "IN" Nothing $ do
  initiator $ do
    e
    s

  responder $ do
    e
    dhee
    dhes

  split

-- | @Noise_XK(s, rs):
--  <- s
--  ...
--  -> e, dhes
--  <- e, dhee
--  -> s, dhse@
noiseXK :: HandshakePattern c
noiseXK = HandshakePattern "XK" (Just pmp) hp
  where
    pmp = responder s

    hp = do
      initiator $ do
        e
        dhes

      responder $ do
        e
        dhee

      initiator $ do
        s
        dhse

      split

-- | @Noise_IK(s, rs):
--  <- s
--  ...
--  -> e, dhes, s, dhss
--  <- e, dhee, dhes@
noiseIK :: HandshakePattern c
noiseIK = HandshakePattern "IK" (Just pmp) hp
  where
    pmp = responder s

    hp = do
      initiator $ do
        e
        dhes
        s
        dhss

      responder $ do
        e
        dhee
        dhes

      split

-- | @Noise_XE(s, rs, re):
--  <- s, e
--  ...
--  -> e, dhee, dhes
--  <- e, dhee
--  -> s, dhse@
noiseXE :: HandshakePattern c
noiseXE = HandshakePattern "XE" (Just pmp) hp
  where
    pmp = responder $ do
      s
      e

    hp = do
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

      split

-- | @Noise_IE(s, rs, re):
--  <- s, e
--  ...
--  -> e, dhee, dhes, s, dhse
--  <- e, dhee, dhes@
noiseIE :: HandshakePattern c
noiseIE = HandshakePattern "IE" (Just pmp) hp
  where
    pmp = responder $ do
      s
      e

    hp = do
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

      split

-- | @Noise_XX(s, rs):
--  -> e
--  <- e, dhee, s, dhse
--  -> s, dhse@
noiseXX :: HandshakePattern c
noiseXX = HandshakePattern "XX" Nothing $ do
  initiator e

  responder $ do
    e
    dhee
    s
    dhse

  initiator $ do
    s
    dhse

  split

-- | @Noise_IX(s, rs):
--  -> e, s
--  <- e, dhee, dhes, s, dhse@
noiseIX :: HandshakePattern c
noiseIX = HandshakePattern "IX" Nothing $ do
  initiator $ do
    e
    s

  responder $ do
    e
    dhee
    dhes
    s
    dhse

  split

-- | @Noise_XR(s, rs):
--  -> e
--  <- e, dhee
--  -> s, dhse
--  <- s, dhse@
noiseXR :: HandshakePattern c
noiseXR = HandshakePattern "XR" Nothing $ do
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

  split

-- | @Noise_N(rs):
--  <- s
--  ...
--  -> e, dhes@
noiseN :: HandshakePattern c
noiseN = HandshakePattern "N" (Just pmp) hp
  where
    pmp = responder s

    hp = do
      initiator $ do
        e
        dhes

      split

-- | @Noise_K(s, rs):
--  -> s
--  <- s
--  ...
--  -> e, dhes, dhss@
noiseK :: HandshakePattern c
noiseK = HandshakePattern "K" (Just pmp) hp
  where
    pmp = do
      initiator s

      responder s

    hp = do
      initiator $ do
        e
        dhes
        dhss

      split

-- | @Noise_X(s, rs):
--  <- s
--  ...
--  -> e, dhes, s, dhss@
noiseX :: HandshakePattern c
noiseX = HandshakePattern "X" (Just pmp) hp
  where
    pmp = responder s

    hp = do
      initiator $ do
        e
        dhes
        s
        dhss

      split
