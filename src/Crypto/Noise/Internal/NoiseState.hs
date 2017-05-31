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
import Crypto.Noise.Internal.SymmetricState (split)

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
    hs                 = handshakeState ho hp
    interpreterResult  = runCatch $ runStateT (resume . runHandshake . runHandshakePattern $ hp) hs
    (suspension, hs'') = case interpreterResult of
      Left err     -> error $ "handshake interpreter threw exception: " <> show err
      Right result -> case result of
        (Left (Request _ resp), hs') -> (Handshake . resp, hs')
        _ -> error "handshake interpreter ended pre-maturely"

-- | Resumes a handshake in progress using the given input data.
resumeHandshake :: (MonadThrow m, Cipher c, DH d, Hash h)
                => ScrubbedBytes
                -> NoiseState c d h
                -> m (NoiseResult, NoiseState c d h)
resumeHandshake msg ns = do
  let interpreterResult = runCatch $ runStateT (resume . runHandshake . (ns ^. nsHandshakeSuspension) $ msg)
                                               $ ns ^. nsHandshakeState
  case interpreterResult of
    -- The interpreter threw an exception. Propagate it up the chain.
    Left err     -> throwM err
    -- The interpreter did not throw an exception. Determine if it finished
    -- running.
    Right (suspension, hs) -> case suspension of
      -- The handshake pattern has not finished running. Save the suspension
      -- and the mutated HandshakeState, and return what was yielded.
      Left (Request req resp) ->
        return (req, ns & nsHandshakeSuspension .~ (Handshake . resp) & nsHandshakeState .~ hs)
      -- The handshake pattern has finished running. Create the CipherStates.
      Right _ -> do
        let (cs1, cs2) = split (hs ^. hsSymmetricState)
            ns'        = if hs ^. hsOpts . hoRole == InitiatorRole
                           then ns & nsSendingCipherState   .~ Just cs1
                                   & nsReceivingCipherState .~ Just cs2
                           else ns & nsSendingCipherState   .~ Just cs2
                                   & nsReceivingCipherState .~ Just cs1
        return (ResultMessage (hs ^. hsMsgBuffer), ns')
