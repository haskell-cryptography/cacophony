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
import Control.Monad.Trans.Free.Church
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
  = PreInitiator (FT TokenF Identity ()) next
  | PreResponder (FT TokenF Identity ()) next
  | Initiator (FT TokenF Identity ()) next
  | Responder (FT TokenF Identity ()) next
  deriving Functor

$(makeFree ''HandshakePatternF)

-- | This type represents a single handshake pattern and is implemented as a
--   Free Monad.
data HandshakePattern =
  HandshakePattern { _hpName    :: ByteString
                   , _hpActions :: FT HandshakePatternF Identity ()
                   }

$(makeLenses ''HandshakePattern)
