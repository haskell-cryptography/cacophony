{-# LANGUAGE TemplateHaskell, DeriveFunctor, FlexibleContexts #-}
{-# OPTIONS_HADDOCK hide #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.HandshakePattern
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.HandshakePattern
  ( -- * Types
    TokenF(..),
    HandshakePatternF(..),
    HandshakePattern(..),
    -- * Functions
    e,
    s,
    dhee,
    dhes,
    dhse,
    dhss,
    initiator,
    responder,
    split,
    hpName,
    hpPreActions,
    hpActions
  ) where

import Data.ByteString (ByteString)
import Control.Lens
import Control.Monad.Free.Church
import Control.Monad.Free.TH

import Crypto.Noise.Internal.CipherState

data TokenF next
  = E next
  | S next
  | Dhee next
  | Dhes next
  | Dhse next
  | Dhss next
  deriving Functor

data HandshakePatternF next
  = Initiator (F TokenF ()) next
  | Responder (F TokenF ()) next
  | Split
  deriving Functor

data HandshakePattern c =
  HandshakePattern { _hpName       :: ByteString
                   , _hpPreActions :: Maybe (F HandshakePatternF ())
                   , _hpActions    :: F HandshakePatternF (CipherState c, CipherState c)
                   }

$(makeFree ''TokenF)

$(makeFree ''HandshakePatternF)

$(makeLenses ''HandshakePattern)
