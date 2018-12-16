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
  -- * Deferred patterns
  , noiseNK1
  , noiseNX1
  , noiseX1N
  , noiseX1K
  , noiseXK1
  , noiseX1K1
  , noiseX1X
  , noiseXX1
  , noiseX1X1
  , noiseK1N
  , noiseK1K
  , noiseKK1
  , noiseK1K1
  , noiseK1X
  , noiseKX1
  , noiseK1X1
  , noiseI1N
  , noiseI1K
  , noiseIK1
  , noiseI1K1
  , noiseI1X
  , noiseIX1
  , noiseI1X1
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

-- | @Noise_NK1:
--  <- s
--  ...
--  -> e
--  <- e, ee, es
noiseNK1 :: HandshakePattern
noiseNK1 = handshakePattern "NK1" $
  preResponder s *>
  initiator e *>
  responder (e *> ee *> es)

-- | @Noise_NX1:
--  -> e
--  <- e, ee, s
--  -> es
noiseNX1 :: HandshakePattern
noiseNX1 = handshakePattern "NX1" $
  initiator e *>
  responder (e *> ee *> s) *>
  initiator es

-- | @Noise_X1N:
--  -> e
--  <- e, ee
--  -> s
--  <- se
noiseX1N :: HandshakePattern
noiseX1N = handshakePattern "X1N" $
  initiator e *>
  responder (e *> ee) *>
  initiator s *>
  responder se

-- | @Noise_X1K:
--  <- s
--  ...
--  -> e, es
--  <- e, ee
--  -> s
--  <- se
noiseX1K :: HandshakePattern
noiseX1K = handshakePattern "X1K" $
  preResponder s *>
  initiator (e *> es) *>
  responder (e *> ee) *>
  initiator s *>
  responder se

-- | @Noise_XK1:
--  <- s
--  ...
--  -> e
--  <- e, ee, es
--  -> s, se
noiseXK1 :: HandshakePattern
noiseXK1 = handshakePattern "XK1" $
  preResponder s *>
  initiator e *>
  responder (e *> ee *> es) *>
  initiator (s *> se)

-- | @Noise_X1K1:
--  <- s
--  ...
--  -> e
--  <- e, ee, es
--  -> s
--  <- se
noiseX1K1 :: HandshakePattern
noiseX1K1 = handshakePattern "X1K1" $
  preResponder s *>
  initiator e *>
  responder (e *> ee *> es) *>
  initiator s *>
  responder se

-- | @Noise_X1X
--  -> e
--  <- e, ee, s, es
--  -> s
--  <- se
noiseX1X :: HandshakePattern
noiseX1X = handshakePattern "X1X" $
  initiator e *>
  responder (e *> ee *> s *> es) *>
  initiator s *>
  responder se

-- | @Noise_XX1:
--  -> e
--  <- e, ee, s
--  -> es, s, se
noiseXX1 :: HandshakePattern
noiseXX1 = handshakePattern "XX1" $
  initiator e *>
  responder (e *> ee *> s) *>
  initiator (es *> s *> se)

-- | @Noise_X1X1:
--  -> e
--  <- e, ee, s
--  -> es, s
--  <- se
noiseX1X1 :: HandshakePattern
noiseX1X1 = handshakePattern "X1X1" $
  initiator e *>
  responder (e *> ee *> s) *>
  initiator (es *> s) *>
  responder se

-- | @Noise_K1N:
--  -> s
--  ...
--  -> e
--  <- e, ee
--  -> se
noiseK1N :: HandshakePattern
noiseK1N = handshakePattern "K1N" $
  preInitiator s *>
  initiator e *>
  responder (e *> ee) *>
  initiator se

-- | @Noise_K1K:
--  -> s
--  <- s
--  ...
--  -> e, es
--  <- e, ee
--  -> se
noiseK1K :: HandshakePattern
noiseK1K = handshakePattern "K1K" $
  preInitiator s *>
  preResponder s *>
  initiator (e *> es) *>
  responder (e *> ee) *>
  initiator se

-- | @Noise_KK1:
--  -> s
--  <- s
--  ...
--  -> e
--  <- e, ee, se, es
noiseKK1 :: HandshakePattern
noiseKK1 = handshakePattern "KK1" $
  preInitiator s *>
  preResponder s *>
  initiator e *>
  responder (e *> ee *> se *> es)

-- | @Noise_K1K1:
--  -> s
--  <- s
--  ...
--  -> e
--  <- e, ee, es
--  -> se
noiseK1K1 :: HandshakePattern
noiseK1K1 = handshakePattern "K1K1" $
  preInitiator s *>
  preResponder s *>
  initiator e *>
  responder (e *> ee *> es) *>
  initiator se

-- | @Noise_K1X
--  -> s
--  ...
--  -> e
--  <- e, ee, s, es
--  -> se
noiseK1X :: HandshakePattern
noiseK1X = handshakePattern "K1X" $
  preInitiator s *>
  initiator e *>
  responder (e *> ee *> s *> es) *>
  initiator se

-- | @Noise_KX1
--  -> s
--  ...
--  -> e
--  <- e, ee, se, s
--  -> es
noiseKX1 :: HandshakePattern
noiseKX1 = handshakePattern "KX1" $
  preInitiator s *>
  initiator e *>
  responder (e *> ee *> se *> s) *>
  initiator es

-- | @Noise_K1X1:
--  -> s
--  ...
--  -> e
--  <- e, ee, s
--  -> se, es
noiseK1X1 :: HandshakePattern
noiseK1X1 = handshakePattern "K1X1" $
  preInitiator s *>
  initiator e *>
  responder (e *> ee *> s) *>
  initiator (se *> es)

-- | @Noise_I1N:
--  -> e, s
--  <- e, ee
--  -> se
noiseI1N :: HandshakePattern
noiseI1N = handshakePattern "I1N" $
  initiator (e *> s) *>
  responder (e *> ee) *>
  initiator se

-- | @Noise_I1K:
--  <- s
--  ...
--  -> e, es, s
--  <- e, ee
--  -> se
noiseI1K :: HandshakePattern
noiseI1K = handshakePattern "I1K" $
  preResponder s *>
  initiator (e *> es *> s) *>
  responder (e *> ee) *>
  initiator se

-- | @Noise_IK1:
--  <- s
--  ...
--  -> e, s
--  <- e, ee, se, es
noiseIK1 :: HandshakePattern
noiseIK1 = handshakePattern "IK1" $
  preResponder s *>
  initiator (e *> s) *>
  responder (e *> ee *> se *> es)

-- | @Noise_I1K1:
--  <- s
--  ...
--  -> e, s
--  <- e, ee, es
--  -> se
noiseI1K1 :: HandshakePattern
noiseI1K1 = handshakePattern "I1K1" $
  preResponder s *>
  initiator (e *> s) *>
  responder (e *> ee *> es) *>
  initiator se

-- | @Noise_I1X:
--  -> e, s
--  <- e, ee, s, es
--  -> se
noiseI1X :: HandshakePattern
noiseI1X = handshakePattern "I1X" $
  initiator (e *> s) *>
  responder (e *> ee *> s *> es) *>
  initiator se

-- | @Noise_IX1:
--  -> e, s
--  <- e, ee, se, s
--  -> es
noiseIX1 :: HandshakePattern
noiseIX1 = handshakePattern "IX1" $
  initiator (e *> s) *>
  responder (e *> ee *> se *> s) *>
  initiator es

-- | @Noise_I1X1:
--  -> e, s
--  <- e, ee, s
--  -> se, es
noiseI1X1 :: HandshakePattern
noiseI1X1 = handshakePattern "I1X1" $
  initiator (e *> s) *>
  responder (e *> ee *> s) *>
  initiator (se *> es)
