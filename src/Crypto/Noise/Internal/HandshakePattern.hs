{-# LANGUAGE TemplateHaskell, DeriveFunctor, FlexibleContexts #-}
{-# OPTIONS_HADDOCK hide #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.HandshakePattern
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.HandshakePattern where

import Control.Lens
import Control.Monad.Free.Church
import Control.Monad.Free.TH
import Data.ByteString (ByteString)

data TokenF next
  = E next
  | S next
  | Dhee next
  | Dhes next
  | Dhse next
  | Dhss next
  deriving Functor

$(makeFree ''TokenF)

data HandshakePatternF next
  = PreInitiator (F TokenF ()) next
  | PreResponder (F TokenF ()) next
  | Initiator (F TokenF ()) next
  | Responder (F TokenF ()) next
  deriving Functor

$(makeFree ''HandshakePatternF)

-- | This type represents a single handshake pattern and is implemented as a
--   Free Monad.
data HandshakePattern =
  HandshakePattern { _hpName    :: ByteString
                   , _hpActions :: F HandshakePatternF ()
                   }

$(makeLenses ''HandshakePattern)
