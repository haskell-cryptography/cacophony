----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.HandshakePatterns
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
--
-- This module contains all of the handshake patterns specified in sections
-- 7.2 and 7.3.
module Crypto.Noise.HandshakePatterns
  ( noiseNN
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
  ) where

import Crypto.Noise.Internal.Handshake.Pattern

-- | @Noise_NN():
--  -> e
--  <- e, ee@
noiseNN :: HandshakePattern
noiseNN = HandshakePattern "NN" $
  initiator e *>
  responder (e *> ee)

-- | @Noise_KN(s):
--  -> s
--  ...
--  -> e
--  <- e, ee, se@
noiseKN :: HandshakePattern
noiseKN = HandshakePattern "KN" $
  preInitiator s *>
  initiator e    *>
  responder (e *> ee *> se)

-- | @Noise_NK(rs):
--  <- s
--  ...
--  -> e, es
--  <- e, ee@
noiseNK :: HandshakePattern
noiseNK = HandshakePattern "NK" $
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
noiseKK = HandshakePattern "KK" $
  preInitiator s            *>
  preResponder s            *>
  initiator (e *> es *> ss) *>
  responder (e *> ee *> se)

-- | @Noise_NX(rs):
--  -> e
--  <- e, ee, s, es@
noiseNX :: HandshakePattern
noiseNX = HandshakePattern "NX" $
  initiator e *>
  responder (e *> ee *> s *> es)

-- | @Noise_KX(s, rs):
--  -> s
--  ...
--  -> e
--  <- e, ee, se, s, es@
noiseKX :: HandshakePattern
noiseKX = HandshakePattern "KX" $
  preInitiator s *>
  initiator e    *>
  responder (e *> ee *> se *> s *> es)

-- | @Noise_XN(s):
--  -> e
--  <- e, ee
--  -> s, se@
noiseXN :: HandshakePattern
noiseXN = HandshakePattern "XN" $
  initiator e         *>
  responder (e *> ee) *>
  initiator (s *> se)

-- | @Noise_IN(s):
--  -> e, s
--  <- e, ee, se@
noiseIN :: HandshakePattern
noiseIN = HandshakePattern "IN" $
  initiator (e *> s) *>
  responder (e *> ee *> se)

-- | @Noise_XK(s, rs):
--  <- s
--  ...
--  -> e, es
--  <- e, ee
--  -> s, se@
noiseXK :: HandshakePattern
noiseXK = HandshakePattern "XK" $
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
noiseIK = HandshakePattern "IK" $
  preResponder s                 *>
  initiator (e *> es *> s *> ss) *>
  responder (e *> ee *> se)

-- | @Noise_XX(s, rs):
--  -> e
--  <- e, ee, s, es
--  -> s, se@
noiseXX :: HandshakePattern
noiseXX = HandshakePattern "XX" $
  initiator e                    *>
  responder (e *> ee *> s *> es) *>
  initiator (s *> se)

-- | @Noise_IX(s, rs):
--  -> e, s
--  <- e, ee, se, s, es@
noiseIX :: HandshakePattern
noiseIX = HandshakePattern "IX" $
  initiator (e *> s) *>
  responder (e *> ee *> se *> s *> es)

-- | @Noise_N(rs):
--  <- s
--  ...
--  -> e, es@
noiseN :: HandshakePattern
noiseN = HandshakePattern "N" $
  preResponder s *>
  initiator (e *> es)

-- | @Noise_K(s, rs):
--  -> s
--  <- s
--  ...
--  -> e, es, ss@
noiseK :: HandshakePattern
noiseK = HandshakePattern "K" $
  preInitiator s *>
  preResponder s *>
  initiator (e *> es *> ss)

-- | @Noise_X(s, rs):
--  <- s
--  ...
--  -> e, es, s, ss@
noiseX :: HandshakePattern
noiseX = HandshakePattern "X" $
  preResponder s *>
  initiator (e *> es *> s *> ss)
