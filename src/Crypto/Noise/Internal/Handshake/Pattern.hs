{-# LANGUAGE TemplateHaskell #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.Handshake.Pattern
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Internal.Handshake.Pattern where

import Control.Applicative.Free
import Control.Lens
import Data.ByteString (ByteString)

data Token next
  = E next
  | S next
  | Ee next
  | Es next
  | Se next
  | Ss next

type MessagePattern = Ap Token

e :: MessagePattern ()
e = liftAp $ E ()

s :: MessagePattern ()
s = liftAp $ S ()

ee :: MessagePattern ()
ee = liftAp $ Ee ()

es :: MessagePattern ()
es = liftAp $ Es ()

se :: MessagePattern ()
se = liftAp $ Se ()

ss :: MessagePattern ()
ss = liftAp $ Ss ()

data Message next
  = PreInitiator (MessagePattern ()) next
  | PreResponder (MessagePattern ()) next
  | Initiator    (MessagePattern ()) next
  | Responder    (MessagePattern ()) next

type MessageSequence = Ap Message

preInitiator :: MessagePattern () -> MessageSequence ()
preInitiator = liftAp . flip PreInitiator ()

preResponder :: MessagePattern () -> MessageSequence ()
preResponder = liftAp . flip PreResponder ()

initiator :: MessagePattern () -> MessageSequence ()
initiator = liftAp . flip Initiator ()

responder :: MessagePattern () -> MessageSequence ()
responder = liftAp . flip Responder ()

data HandshakePattern = HandshakePattern
  { _hpName   :: ByteString
  , _hpMsgSeq :: MessageSequence ()
  }

$(makeLenses ''HandshakePattern)
