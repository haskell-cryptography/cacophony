-------------------------------------------------
-- |
-- Module      : Crypto.Noise.HandshakePatterns
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
--
-- This module contains all of the handshake patterns specified in sections
-- 7.2, 7.3, and 9.4.
module Crypto.Noise.HandshakePatterns
  ( -- * Standard patterns
    noiseNN
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
  -- * PSK patterns
  , noiseNNpsk0
  , noiseNNpsk2
  , noiseNKpsk0
  , noiseNKpsk2
  , noiseNXpsk2
  , noiseXNpsk3
  , noiseXKpsk3
  , noiseXXpsk3
  , noiseKNpsk0
  , noiseKNpsk2
  , noiseKKpsk0
  , noiseKKpsk2
  , noiseKXpsk2
  , noiseINpsk1
  , noiseINpsk2
  , noiseIKpsk1
  , noiseIKpsk2
  , noiseIXpsk2
  , noiseNpsk0
  , noiseKpsk0
  , noiseXpsk1
  ) where

import Crypto.Noise.Internal.Handshake.Pattern

-- | @Noise_NN():
--  -> e
--  <- e, ee@
noiseNN :: HandshakePattern
noiseNN = handshakePattern "NN" $
  initiator e *>
  responder (e *> ee)

-- | @Noise_KN(s):
--  -> s
--  ...
--  -> e
--  <- e, ee, se@
noiseKN :: HandshakePattern
noiseKN = handshakePattern "KN" $
  preInitiator s *>
  initiator e    *>
  responder (e *> ee *> se)

-- | @Noise_NK(rs):
--  <- s
--  ...
--  -> e, es
--  <- e, ee@
noiseNK :: HandshakePattern
noiseNK = handshakePattern "NK" $
  preResponder s      *>
  initiator (e *> es) *>
  responder (e *> ee)

-- | @Noise_KK(s, rs):
--  -> s
--  <- s
--  ...
--  -> e, es, ss
--  <- e, ee, se@
noiseKK :: HandshakePattern
noiseKK = handshakePattern "KK" $
  preInitiator s            *>
  preResponder s            *>
  initiator (e *> es *> ss) *>
  responder (e *> ee *> se)

-- | @Noise_NX(rs):
--  -> e
--  <- e, ee, s, es@
noiseNX :: HandshakePattern
noiseNX = handshakePattern "NX" $
  initiator e *>
  responder (e *> ee *> s *> es)

-- | @Noise_KX(s, rs):
--  -> s
--  ...
--  -> e
--  <- e, ee, se, s, es@
noiseKX :: HandshakePattern
noiseKX = handshakePattern "KX" $
  preInitiator s *>
  initiator e    *>
  responder (e *> ee *> se *> s *> es)

-- | @Noise_XN(s):
--  -> e
--  <- e, ee
--  -> s, se@
noiseXN :: HandshakePattern
noiseXN = handshakePattern "XN" $
  initiator e         *>
  responder (e *> ee) *>
  initiator (s *> se)

-- | @Noise_IN(s):
--  -> e, s
--  <- e, ee, se@
noiseIN :: HandshakePattern
noiseIN = handshakePattern "IN" $
  initiator (e *> s) *>
  responder (e *> ee *> se)

-- | @Noise_XK(s, rs):
--  <- s
--  ...
--  -> e, es
--  <- e, ee
--  -> s, se@
noiseXK :: HandshakePattern
noiseXK = handshakePattern "XK" $
  preResponder s      *>
  initiator (e *> es) *>
  responder (e *> ee) *>
  initiator (s *> se)

-- | @Noise_IK(s, rs):
--  <- s
--  ...
--  -> e, es, s, ss
--  <- e, ee, se@
noiseIK :: HandshakePattern
noiseIK = handshakePattern "IK" $
  preResponder s                 *>
  initiator (e *> es *> s *> ss) *>
  responder (e *> ee *> se)

-- | @Noise_XX(s, rs):
--  -> e
--  <- e, ee, s, es
--  -> s, se@
noiseXX :: HandshakePattern
noiseXX = handshakePattern "XX" $
  initiator e                    *>
  responder (e *> ee *> s *> es) *>
  initiator (s *> se)

-- | @Noise_IX(s, rs):
--  -> e, s
--  <- e, ee, se, s, es@
noiseIX :: HandshakePattern
noiseIX = handshakePattern "IX" $
  initiator (e *> s) *>
  responder (e *> ee *> se *> s *> es)

-- | @Noise_N(rs):
--  <- s
--  ...
--  -> e, es@
noiseN :: HandshakePattern
noiseN = handshakePattern "N" $
  preResponder s *>
  initiator (e *> es)

-- | @Noise_K(s, rs):
--  -> s
--  <- s
--  ...
--  -> e, es, ss@
noiseK :: HandshakePattern
noiseK = handshakePattern "K" $
  preInitiator s *>
  preResponder s *>
  initiator (e *> es *> ss)

-- | @Noise_X(s, rs):
--  <- s
--  ...
--  -> e, es, s, ss@
noiseX :: HandshakePattern
noiseX = handshakePattern "X" $
  preResponder s *>
  initiator (e *> es *> s *> ss)

-- | @Noise_NNpsk0():
--  -> psk, e
--  <- e, ee@
noiseNNpsk0 :: HandshakePattern
noiseNNpsk0 = handshakePattern "NNpsk0" $
  initiator (psk *> e) *>
  responder (e *> ee)

-- | @Noise_NNpsk2():
--  -> e
--  <- e, ee, psk@
noiseNNpsk2 :: HandshakePattern
noiseNNpsk2 = handshakePattern "NNpsk2" $
  initiator e *>
  responder (e *> ee *> psk)

-- | @Noise_NKpsk0(rs):
--  <- s
--  ...
--  -> psk, e, es
--  <- e, ee@
noiseNKpsk0 :: HandshakePattern
noiseNKpsk0 = handshakePattern "NKpsk0" $
  preResponder s *>
  initiator (psk *> e *> es) *>
  responder (e *> ee)

-- | @Noise_NKpsk2(rs):
--  <- s
--  ...
--  -> e, es
--  <- e, ee, psk@
noiseNKpsk2 :: HandshakePattern
noiseNKpsk2 = handshakePattern "NKpsk2" $
  preResponder s *>
  initiator (e *> es) *>
  responder (e *> ee *> psk)

-- | @Noise_NXpsk2(rs):
--  -> e
--  <- e, ee, s, es, psk@
noiseNXpsk2 :: HandshakePattern
noiseNXpsk2 = handshakePattern "NXpsk2" $
  initiator e *>
  responder (e *> ee *> s *> es *> psk)

-- | @Noise_XNpsk3(s):
--  -> e
--  <- e, ee
--  -> s, se, psk@
noiseXNpsk3 :: HandshakePattern
noiseXNpsk3 = handshakePattern "XNpsk3" $
  initiator e *>
  responder (e *> ee) *>
  initiator (s *> se *> psk)

-- | @Noise_XKpsk3(s, rs):
--  <- s
--  ...
--  -> e, es
--  <- e, ee
--  -> s, se, psk@
noiseXKpsk3 :: HandshakePattern
noiseXKpsk3 = handshakePattern "XKpsk3" $
  preResponder s *>
  initiator (e *> es) *>
  responder (e *> ee) *>
  initiator (s *> se *> psk)

-- | @Noise_XXpsk3(s, rs):
--  -> e
--  <- e, ee, s, es
--  -> s, se, psk@
noiseXXpsk3 :: HandshakePattern
noiseXXpsk3 = handshakePattern "XXpsk3" $
  initiator e *>
  responder (e *> ee *> s *> es) *>
  initiator (s *> se *> psk)

-- | @Noise_KNpsk0(s):
--  -> s
--  ...
--  -> psk, e
--  <- e, ee, se@
noiseKNpsk0 :: HandshakePattern
noiseKNpsk0 = handshakePattern "KNpsk0" $
  preInitiator s *>
  initiator (psk *> e) *>
  responder (e *> ee *> se)

-- | @Noise_KNpsk2(s):
--  -> s
--  ...
--  -> e
--  <- e, ee, se, psk@
noiseKNpsk2 :: HandshakePattern
noiseKNpsk2 = handshakePattern "KNpsk2" $
  preInitiator s *>
  initiator e *>
  responder (e *> ee *> se *> psk)

-- | @Noise_KKpsk0(s, rs):
--  -> s
--  <- s
--  ...
--  -> psk, e, es, ss
--  <- e, ee, se@
noiseKKpsk0 :: HandshakePattern
noiseKKpsk0 = handshakePattern "KKpsk0" $
  preInitiator s *>
  preResponder s *>
  initiator (psk *> e *> es *> ss) *>
  responder (e *> ee *> se)

-- | @Noise_KKpsk2(s, rs):
--  -> s
--  <- s
--  ...
--  -> e, es, ss
--  <- e, ee, se, psk@
noiseKKpsk2 :: HandshakePattern
noiseKKpsk2 = handshakePattern "KKpsk2" $
  preInitiator s *>
  preResponder s *>
  initiator (e *> es *> ss) *>
  responder (e *> ee *> se *> psk)

-- | @Noise_KXpsk2(s, rs):
--  -> s
--  ...
--  -> e
--  <- e, ee, se, s, es, psk@
noiseKXpsk2 :: HandshakePattern
noiseKXpsk2 = handshakePattern "KXpsk2" $
  preInitiator s *>
  initiator e *>
  responder (e *> ee *> se *> s *> es *> psk)

-- | @Noise_INpsk1(s):
--  -> e, s, psk
--  <- e, ee, se@
noiseINpsk1 :: HandshakePattern
noiseINpsk1 = handshakePattern "INpsk1" $
  initiator (e *> s *> psk) *>
  responder (e *> ee *> se)

-- | @Noise_INpsk2(s):
--  -> e, s
--  <- e, ee, se, psk@
noiseINpsk2 :: HandshakePattern
noiseINpsk2 = handshakePattern "INpsk2" $
  initiator (e *> s) *>
  responder (e *> ee *> se *> psk)

-- | @Noise_IKpsk1(s, rs):
--  <- s
--  ...
--  -> e, es, s, ss, psk
--  <- e, ee, se@
noiseIKpsk1 :: HandshakePattern
noiseIKpsk1 = handshakePattern "IKpsk1" $
  preResponder s *>
  initiator (e *> es *> s *> ss *> psk) *>
  responder (e *> ee *> se)

-- | @Noise_IKpsk2(s, rs):
--  <- s
--  ...
--  -> e, es, s, ss
--  <- e, ee, se, psk@
noiseIKpsk2 :: HandshakePattern
noiseIKpsk2 = handshakePattern "IKpsk2" $
  preResponder s *>
  initiator (e *> es *> s *> ss) *>
  responder (e *> ee *> se *> psk)

-- | @Noise_IXpsk2(s, rs):
--  -> e, s
--  <- e, ee, se, s, es, psk@
noiseIXpsk2 :: HandshakePattern
noiseIXpsk2 = handshakePattern "IXpsk2" $
  initiator (e *> s) *>
  responder (e *> ee *> se *> s *> es *> psk)

-- | @Noise_Npsk0(rs):
--  <- s
--  ...
--  -> psk, e, es@
noiseNpsk0 :: HandshakePattern
noiseNpsk0 = handshakePattern "Npsk0" $
  preResponder s *>
  initiator (psk *> e *> es)

-- | @Noise_Kpsk0(s, rs):
--  <- s
--  ...
--  -> psk, e, es, ss@
noiseKpsk0 :: HandshakePattern
noiseKpsk0 = handshakePattern "Kpsk0" $
  preInitiator s *>
  preResponder s *>
  initiator (psk *> e *> es *> ss)

-- | @Noise_Xpsk1(s, rs):
--  <- s
--  ...
--  -> e, es, s, ss, psk@
noiseXpsk1 :: HandshakePattern
noiseXpsk1 = handshakePattern "Xpsk1" $
  preResponder s *>
  initiator (e *> es *> s *> ss *> psk)
