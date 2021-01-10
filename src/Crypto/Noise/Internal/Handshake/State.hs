{-# LANGUAGE TemplateHaskell, ScopedTypeVariables, GeneralizedNewtypeDeriving,
             FlexibleInstances, MultiParamTypeClasses, UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.Handshake.State
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Internal.Handshake.State where

import Control.Lens ( (^.), makeLenses )
import Control.Monad.Coroutine ( Coroutine(Coroutine) )
import Control.Monad.Coroutine.SuspensionFunctors ( Request )
import Control.Monad.Catch.Pure ( MonadThrow(..), Catch )
import Control.Monad.State       (MonadState(..), StateT)
import Control.Monad.Trans.Class (MonadTrans(lift))
import Data.ByteArray            (ScrubbedBytes, convert)
import Data.ByteString           (ByteString)
import Data.Proxy ( Proxy(..) )

import Crypto.Noise.Cipher ( Plaintext, Cipher(cipherName) )
import Crypto.Noise.DH ( KeyPair, DH(dhName, PublicKey) )
import Crypto.Noise.Hash ( Hash(hashName) )
import Crypto.Noise.Internal.Handshake.Pattern
    ( HandshakePattern, hpName, hpPSKMode )
import Crypto.Noise.Internal.SymmetricState
    ( SymmetricState, symmetricState, mixHash )

-- | Represents the side of the conversation upon which a party resides.
data HandshakeRole = InitiatorRole | ResponderRole
                     deriving (Show, Eq)

-- | Represents the various options and keys for a handshake parameterized by
--   the 'DH' method.
data HandshakeOpts d =
  HandshakeOpts { _hoRole                :: HandshakeRole
                , _hoPrologue            :: Plaintext
                , _hoLocalEphemeral      :: Maybe (KeyPair d)
                , _hoLocalStatic         :: Maybe (KeyPair d)
                , _hoRemoteEphemeral     :: Maybe (PublicKey d)
                , _hoRemoteStatic        :: Maybe (PublicKey d)
                }

$(makeLenses ''HandshakeOpts)

-- | Holds all state associated with the interpreter.
data HandshakeState c d h =
  HandshakeState { _hsSymmetricState :: SymmetricState c h
                 , _hsOpts           :: HandshakeOpts d
                 , _hsPSKMode        :: Bool
                 , _hsMsgBuffer      :: ScrubbedBytes
                 }

$(makeLenses ''HandshakeState)

-- | This data structure is yielded by the coroutine when more data is needed.
data HandshakeResult
  = HandshakeResultMessage ScrubbedBytes
  | HandshakeResultNeedPSK

-- | All HandshakePattern interpreters run within this Monad.
newtype Handshake c d h r =
  Handshake { runHandshake :: Coroutine (Request HandshakeResult ScrubbedBytes) (StateT (HandshakeState c d h) Catch) r
            } deriving ( Functor
                       , Applicative
                       , Monad
                       , MonadThrow
                       , MonadState (HandshakeState c d h)
                       )

-- | @defaultHandshakeOpts role prologue@ returns a default set of handshake
--   options. All keys are set to 'Nothing'.
defaultHandshakeOpts :: HandshakeRole
                     -> Plaintext
                     -> HandshakeOpts d
defaultHandshakeOpts r p =
  HandshakeOpts { _hoRole                = r
                , _hoPrologue            = p
                , _hoLocalEphemeral      = Nothing
                , _hoLocalStatic         = Nothing
                , _hoRemoteEphemeral     = Nothing
                , _hoRemoteStatic        = Nothing
                }

-- | Sets the local ephemeral key.
setLocalEphemeral :: Maybe (KeyPair d)
                  -> HandshakeOpts d
                  -> HandshakeOpts d
setLocalEphemeral k opts = opts { _hoLocalEphemeral = k }

-- | Sets the local static key.
setLocalStatic :: Maybe (KeyPair d)
               -> HandshakeOpts d
               -> HandshakeOpts d
setLocalStatic k opts = opts { _hoLocalStatic = k }

-- | Sets the remote ephemeral key (rarely needed).
setRemoteEphemeral :: Maybe (PublicKey d)
                   -> HandshakeOpts d
                   -> HandshakeOpts d
setRemoteEphemeral k opts = opts { _hoRemoteEphemeral = k }

-- | Sets the remote static key.
setRemoteStatic :: Maybe (PublicKey d)
                -> HandshakeOpts d
                -> HandshakeOpts d
setRemoteStatic k opts = opts { _hoRemoteStatic = k }

-- | Given a protocol name, returns the full handshake name according to the
--   rules in section 8.
mkHandshakeName :: forall c d h proxy. (Cipher c, DH d, Hash h)
                => ByteString
                -> proxy (c, d, h)
                -> ScrubbedBytes
mkHandshakeName protoName _ =
  "Noise_" <> convert protoName <> "_" <> d <> "_" <> c <> "_" <> h
  where
    c = cipherName (Proxy :: Proxy c)
    d = dhName     (Proxy :: Proxy d)
    h = hashName   (Proxy :: Proxy h)

-- | Constructs a HandshakeState from a given set of options and a protocol
--   name (such as "NN" or "IK").
handshakeState :: forall c d h. (Cipher c, DH d, Hash h)
               => HandshakeOpts d
               -> HandshakePattern
               -> HandshakeState c d h
handshakeState ho hp =
  HandshakeState { _hsSymmetricState = ss'
                 , _hsOpts           = ho
                 , _hsPSKMode        = hp ^. hpPSKMode
                 , _hsMsgBuffer      = mempty
                 }
  where
    ss  = symmetricState $ mkHandshakeName (hp ^. hpName)
                                           (Proxy :: Proxy (c, d, h))
    ss' = mixHash (ho ^. hoPrologue) ss

instance (Functor f, MonadThrow m) => MonadThrow (Coroutine f m) where
  throwM = lift . throwM

instance (Functor f, MonadState s m) => MonadState s (Coroutine f m) where
  get = lift get
  put = lift . put
  state = lift . state
