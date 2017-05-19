{-# LANGUAGE TemplateHaskell #-}
--------------------------------------------------------
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
  = E   next
  | S   next
  | Ee  next
  | Es  next
  | Se  next
  | Ss  next
  | Psk next

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

psk :: MessagePattern ()
psk = liftAp $ Psk ()

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
  { _hpName    :: ByteString
  , _hpPSKMode :: Bool
  , _hpMsgSeq  :: MessageSequence ()
  }

$(makeLenses ''HandshakePattern)

newtype HasPSK = HasPSK { unPSK :: Bool }

-- | Smart constructor for HandshakePatterns.
handshakePattern :: ByteString
                 -> MessageSequence ()
                 -> HandshakePattern
handshakePattern protoName ms = HandshakePattern protoName hasPSK ms
  where
    hasPSK = unPSK $ runAp_ scanS ms

    scanS (PreInitiator _ _) = mempty
    scanS (PreResponder _ _) = mempty
    scanS (Initiator   mp _) = runAp_ scanP mp
    scanS (Responder   mp _) = runAp_ scanP mp

    scanP (Psk _) = HasPSK True
    scanP _       = mempty

instance Monoid HasPSK where
  mempty = HasPSK False
  (HasPSK a) `mappend` (HasPSK b) = HasPSK $ a || b
