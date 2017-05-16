----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.HandshakeInterpreter
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Internal.HandshakeInterpreter where

import Control.Applicative.Free
import Control.Lens

import Crypto.Noise.Internal.HandshakePattern

interpretToken :: Token a -> IO a
interpretToken (E  next) = return next
interpretToken (S  next) = return next
interpretToken (Ee next) = return next
interpretToken (Es next) = return next
interpretToken (Se next) = return next
interpretToken (Ss next) = return next

runMessagePattern :: MessagePattern () -> IO ()
runMessagePattern = runAp interpretToken

interpretMessage :: Message a -> IO a
interpretMessage (PreInitiator _  next) = return next
interpretMessage (PreResponder _  next) = return next
interpretMessage (Initiator mp next) = do
  runMessagePattern mp
  return next

interpretMessage (Responder mp next) = do
  runMessagePattern mp
  return next

runHandshakePattern :: HandshakePattern -> IO ()
runHandshakePattern hp = runAp interpretMessage $ hp ^. hpMsgSeq
