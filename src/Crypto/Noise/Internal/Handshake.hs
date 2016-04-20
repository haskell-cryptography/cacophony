{-# LANGUAGE TemplateHaskell, GeneralizedNewtypeDeriving, FlexibleInstances,
    MultiParamTypeClasses, UndecidableInstances #-}
{-# OPTIONS_HADDOCK hide #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.Handshake
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.Handshake where

import Control.Lens
import Control.Monad.Coroutine
import Control.Monad.Coroutine.SuspensionFunctors
import Control.Monad.Except (MonadError(..), Except)
import Control.Monad.State  (MonadState(..), StateT)
import Control.Monad.Trans.Class (MonadTrans(lift))

import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Internal.HandshakePattern
import Crypto.Noise.Internal.SymmetricState
import Data.ByteArray.Extend

-- | Represents the various exceptions which can be thrown.
--
--   * 'InvalidHandshakeOptions' occurs when a key that is needed is missing, or
--   when a key is provided that shouldn't be. For example, it would be an
--   error for the initiator to provide a remote static key if using the
--   @Noise_NX@ pattern, because that key is transmitted during the
--   handshake.
--
--   * 'DecryptionError' occurs when a non-handshake message fails to be
--   decrypted.
--
--   * 'HandshakeError' occurs when a handshake message fails to be
--   processed. This can be due to an invalid transmitted ephemeral key,
--   a transmitted static key which fails to be decrypted, or a handshake
--   message payload which fails to be decrypted.
data NoiseException = InvalidHandshakeOptions String
                    | DecryptionError String
                    | HandshakeError String
                    deriving Show

-- | Represents the side of the conversation upon which a party resides.
data HandshakeRole = InitiatorRole | ResponderRole
                     deriving Eq

-- | Represents the various options which define a handshake.
data HandshakeOpts d =
  HandshakeOpts { _hoPattern             :: HandshakePattern
                , _hoRole                :: HandshakeRole
                , _hoPrologue            :: Plaintext
                , _hoPreSharedKey        :: Maybe Plaintext
                , _hoLocalStatic         :: Maybe (KeyPair d)
                , _hoLocalSemiEphemeral  :: Maybe (KeyPair d)
                , _hoLocalEphemeral      :: Maybe (KeyPair d)
                , _hoRemoteStatic        :: Maybe (PublicKey d)
                , _hoRemoteSemiEphemeral :: Maybe (PublicKey d)
                , _hoRemoteEphemeral     :: Maybe (PublicKey d)
                }

$(makeLenses ''HandshakeOpts)

data HandshakeState c d h =
  HandshakeState { _hsSymmetricState :: SymmetricState c h
                 , _hsOpts           :: HandshakeOpts d
                 , _hsMsgBuffer      :: ScrubbedBytes
                 }

$(makeLenses ''HandshakeState)

newtype Handshake c d h r =
  Handshake { runHandshake' :: Coroutine (Request ScrubbedBytes ScrubbedBytes) (StateT (HandshakeState c d h) (Except NoiseException)) r
            } deriving ( Functor
                       , Applicative
                       , Monad
                       , MonadError NoiseException
                       , MonadState (HandshakeState c d h)
                       )

instance (Functor f, MonadError e m) => MonadError e (Coroutine f m) where
  throwError = lift . throwError
  catchError m _ = m

instance (Functor f, MonadState s m) => MonadState s (Coroutine f m) where
  get = lift get
  put = lift . put
  state = lift . state
