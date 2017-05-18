{-# LANGUAGE TemplateHaskell, ScopedTypeVariables #-}
-------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.NoiseState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Internal.NoiseState where

import Control.Lens
import Control.Monad.Catch.Pure
import Control.Monad.Coroutine
import Control.Monad.Coroutine.SuspensionFunctors
import Control.Monad.State
import Data.ByteArray (ScrubbedBytes)
import Data.Monoid    ((<>))

import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.Handshake.Interpreter
import Crypto.Noise.Internal.Handshake.Pattern
import Crypto.Noise.Internal.Handshake.State

-- | Represents the complete state of a Noise conversation.
data NoiseState c d h =
  NoiseState { _nsHandshakeState       :: HandshakeState c d h
             , _nsHandshakeSuspension  :: ScrubbedBytes -> Handshake c d h ()
             , _nsSendingCipherState   :: Maybe (CipherState c)
             , _nsReceivingCipherState :: Maybe (CipherState c)
             }

$(makeLenses ''NoiseState)

-- | Creates a NoiseState from the given handshake options.
noiseState :: (Cipher c, DH d, Hash h)
           => HandshakeOpts d
           -> HandshakePattern
           -> NoiseState c d h
noiseState ho hp =
  NoiseState { _nsHandshakeState       = hs''
             , _nsHandshakeSuspension  = suspension
             , _nsSendingCipherState   = Nothing
             , _nsReceivingCipherState = Nothing
             }

  where
    hs                 = handshakeState ho $ hp ^. hpName
    interpreterResult  = runCatch $ runStateT (resume . runHandshake . runHandshakePattern $ hp) hs
    (suspension, hs'') = case interpreterResult of
      Left err -> error $ "handshake interpreter threw exception: " <> show err
      Right result -> case result of
        (Left (Request _ resp), hs') -> (Handshake . resp, hs')
        _ -> error "handshake interpreter ended pre-maturely"
