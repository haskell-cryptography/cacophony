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

import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.Handshake.Interpreter
import Crypto.Noise.Internal.Handshake.Pattern (HandshakePattern)
import Crypto.Noise.Internal.Handshake.State
import Crypto.Noise.Internal.SymmetricState (split)

-- | This type represents the state of an entire Noise conversation, and it is
--   used both during the handshake and for every message read and written
--   thereafter (transport messages). It is parameterized by the 'Cipher', 'DH'
--   method, and 'Hash' to be used.
data NoiseState c d h =
  NoiseState { _nsHandshakeState       :: HandshakeState c d h
             , _nsHandshakePattern     :: HandshakePattern
             , _nsHandshakeSuspension  :: Maybe (ScrubbedBytes -> Handshake c d h ())
             , _nsSendingCipherState   :: Maybe (CipherState c)
             , _nsReceivingCipherState :: Maybe (CipherState c)
             }

$(makeLenses ''NoiseState)

-- | Creates a 'NoiseState' from the given handshake options and pattern.
noiseState :: (Cipher c, DH d, Hash h)
           => HandshakeOpts d
           -> HandshakePattern
           -> NoiseState c d h
noiseState ho hp =
  NoiseState { _nsHandshakeState       = handshakeState ho hp
             , _nsHandshakePattern     = hp
             , _nsHandshakeSuspension  = Nothing
             , _nsSendingCipherState   = Nothing
             , _nsReceivingCipherState = Nothing
             }

-- | Resumes a handshake in progress using the given input data.
resumeHandshake :: (MonadThrow m, Cipher c, DH d, Hash h)
                => ScrubbedBytes
                -> NoiseState c d h
                -> m (HandshakeResult, NoiseState c d h)
resumeHandshake msg ns = case ns ^. nsHandshakeSuspension of
  Nothing -> do
    let hp = ns ^. nsHandshakePattern
    (_, ns') <- runInterpreter . runHandshakePattern $ hp
    resumeHandshake msg ns'

  Just s -> runInterpreter . s $ msg

  where
    runInterpreter i = do
      let result = runCatch . runStateT (resume . runHandshake $ i)
                                        $ ns ^. nsHandshakeState
      case result of
        -- The interpreter threw an exception. Propagate it up the chain.
        Left err -> throwM err
        -- The interpreter did not throw an exception. Determine if it finished
        -- running.
        Right (suspension, hs) -> case suspension of
          -- The handshake pattern has not finished running. Save the suspension
          -- and the mutated HandshakeState and return what was yielded.
          Left (Request req resp) -> do
            let ns' = ns & nsHandshakeSuspension .~ Just (Handshake . resp)
                         & nsHandshakeState      .~ hs
            return (req, ns')
          -- The handshake pattern has finished running. Create the CipherStates.
          Right _ -> do
            let (cs1, cs2) = split (hs ^. hsSymmetricState)

                ns'        = if hs ^. hsOpts . hoRole == InitiatorRole
                               then ns & nsSendingCipherState   .~ Just cs1
                                       & nsReceivingCipherState .~ Just cs2
                               else ns & nsSendingCipherState   .~ Just cs2
                                       & nsReceivingCipherState .~ Just cs1

                ns''       = ns' & nsHandshakeState .~ hs

            return (HandshakeResultMessage (hs ^. hsMsgBuffer), ns'')
