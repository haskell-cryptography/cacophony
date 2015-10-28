{-# LANGUAGE OverloadedStrings, FlexibleInstances,
    GeneralizedNewtypeDeriving, TemplateHaskell,
    RankNTypes, FlexibleContexts, ScopedTypeVariables #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.HandshakeState
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.HandshakeState
  ( -- * Classes
    MonadHandshake(..),
    -- * Types
    HandshakeState,
    Descriptor,
    DescriptorIO,
    -- * Functions
    runDescriptorT,
    getRemoteStaticKey,
    handshakeState,
    writeHandshakeMsg,
    readHandshakeMsg,
    writeHandshakeMsgFinal,
    readHandshakeMsgFinal,
    encryptPayload,
    decryptPayload
  ) where

import Control.Lens hiding (re)
import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B (append, splitAt)
import Data.Maybe (fromMaybe)
import Data.Proxy

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.SymmetricHandshakeState
import Crypto.Noise.Types

data HandshakeState c d h =
  HandshakeState { _hssSymmetricHandshake :: SymmetricHandshakeState c h
                 , _hssLocalStaticKey     :: Maybe (KeyPair d)
                 , _hssLocalEphemeralKey  :: Maybe (KeyPair d)
                 , _hssRemoteStaticKey    :: Maybe (PublicKey d)
                 , _hssRemoteEphemeralKey :: Maybe (PublicKey d)
                 }

$(makeLenses ''HandshakeState)

newtype DescriptorT c d h m a = DescriptorT { unD :: StateT (HandshakeState c d h) m a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadState(HandshakeState c d h))

type Descriptor c d h a = DescriptorT c d h Identity a

type DescriptorIO c d h a = DescriptorT c d h IO a

runDescriptorT :: Monad m => DescriptorT c d h m a -> HandshakeState c d h -> m (a, HandshakeState c d h)
runDescriptorT = runStateT . unD

class Monad m => MonadHandshake m where
  tokenPreLS :: m ()
  tokenPreRS :: m ()
  tokenPreLE :: m ()
  tokenPreRE :: m ()
  tokenRE   :: ByteString -> m ByteString
  tokenRS   :: ByteString -> m ByteString
  tokenWE   :: MonadIO m => m ByteString
  tokenWS   :: m ByteString
  tokenDHEE :: m ()
  tokenDHES :: m ()
  tokenDHSE :: m ()
  tokenDHSS :: m ()

instance (Monad m, Cipher c, Curve d, Hash h) => MonadHandshake (DescriptorT c d h m) where
  tokenPreLS = tokenPreLX hssLocalStaticKey

  tokenPreRS = tokenPreRX hssRemoteStaticKey

  tokenPreLE = tokenPreLX hssLocalEphemeralKey

  tokenPreRE = tokenPreRX hssRemoteEphemeralKey

  tokenRE buf = tokenRX buf hssRemoteEphemeralKey

  tokenRS buf = tokenRX buf hssRemoteStaticKey

  tokenWE = do
    ~kp@(_, pk) <- liftIO curveGenKey
    hs <- get
    let pk'        = curvePubToBytes pk
        shs        = hs ^. hssSymmetricHandshake
        (ct, shs') = encryptAndHash (Plaintext pk') shs
    put $ hs & hssLocalEphemeralKey .~ Just kp & hssSymmetricHandshake .~ shs'
    return . convert $ ct

  tokenWS = do
    hs <- get
    let pk         = curvePubToBytes . snd . getLocalStaticKey $ hs
        shs        = hs ^. hssSymmetricHandshake
        (ct, shs') = encryptAndHash ((Plaintext . convert) pk) shs
    put $ hs & hssSymmetricHandshake .~ shs'
    return . convert $ ct

  tokenDHEE = do
    hs <- get
    let shs      = hs ^. hssSymmetricHandshake
        ~(sk, _) = getLocalEphemeralKey hs
        rpk      = getRemoteEphemeralKey hs
        dh       = curveDH sk rpk
        shs'     = mixKey dh shs
    put $ hs & hssSymmetricHandshake .~ shs'

  tokenDHES = do
    hs <- get
    let shs      = hs ^. hssSymmetricHandshake
        ~(sk, _) = getLocalEphemeralKey hs
        rpk      = getRemoteStaticKey hs
        dh       = curveDH sk rpk
        shs'     = mixKey dh shs
    put $ hs & hssSymmetricHandshake .~ shs'

  tokenDHSE = do
    hs <- get
    let shs      = hs ^. hssSymmetricHandshake
        ~(sk, _) = getLocalStaticKey hs
        rpk      = getRemoteEphemeralKey hs
        dh       = curveDH sk rpk
        shs'     = mixKey dh shs
    put $ hs & hssSymmetricHandshake .~ shs'

  tokenDHSS = do
    hs <- get
    let shs      = hs ^. hssSymmetricHandshake
        ~(sk, _) = getLocalStaticKey hs
        rpk      = getRemoteStaticKey hs
        dh       = curveDH sk rpk
        shs'     = mixKey dh shs
    put $ hs & hssSymmetricHandshake .~ shs'

getLocalStaticKey :: Curve d => HandshakeState c d h -> KeyPair d
getLocalStaticKey hs = fromMaybe (error "local static key not set")
                                 (hs ^. hssLocalStaticKey)

getLocalEphemeralKey :: Curve d => HandshakeState c d h -> KeyPair d
getLocalEphemeralKey hs = fromMaybe (error "local ephemeral key not set")
                                    (hs ^. hssLocalEphemeralKey)

getRemoteStaticKey :: Curve d => HandshakeState c d h -> PublicKey d
getRemoteStaticKey hs = fromMaybe (error "remote static key not set")
                                  (hs ^. hssRemoteStaticKey)

getRemoteEphemeralKey :: Curve d => HandshakeState c d h -> PublicKey d
getRemoteEphemeralKey hs = fromMaybe (error "remote ephemeral key not set")
                                     (hs ^. hssRemoteEphemeralKey)

tokenPreLX :: (MonadState (HandshakeState c d h) m, Cipher c, Curve d, Hash h)
           => Lens' (HandshakeState c d h) (Maybe (KeyPair d))
           -> m ()
tokenPreLX keyToView = do
  hs <- get
  let shs     = hs ^. hssSymmetricHandshake
      (_, pk) = fromMaybe (error "tokenPreLX: local key not set") (hs ^. keyToView)
      shs'    = mixHash (curvePubToBytes pk) shs
  put $ hs & hssSymmetricHandshake .~ shs'

tokenPreRX :: (MonadState (HandshakeState c d h) m, Cipher c, Curve d, Hash h)
           => Lens' (HandshakeState c d h) (Maybe (PublicKey d))
           -> m ()
tokenPreRX keyToView = do
  hs <- get
  let shs  = hs ^. hssSymmetricHandshake
      pk   = fromMaybe (error "tokenPreRX: remote key not set") (hs ^. keyToView)
      shs' = mixHash (curvePubToBytes pk) shs
  put $ hs & hssSymmetricHandshake .~ shs'

tokenRX :: forall c d h m. (MonadState (HandshakeState c d h) m, Cipher c, Curve d, Hash h)
       => ByteString
       -> Lens' (HandshakeState c d h) (Maybe (PublicKey d))
       -> m ByteString
tokenRX buf keyToUpdate = do
  hs <- get

  let hasKey    = hs ^. hssSymmetricHandshake . shsHasKey
      (b, rest) = B.splitAt (d hasKey) buf
      ct        = cipherBytesToText . convert $ b
      shs       = hs ^. hssSymmetricHandshake
      (Plaintext pt, shs') = decryptAndHash ct shs

  put $ hs & keyToUpdate .~ Just (curveBytesToPub pt) & hssSymmetricHandshake .~ shs'

  return rest

  where
    len           = curveLength (Proxy :: Proxy d)
    d hk
      | hk        = len + 16
      | otherwise = len

handshakeState :: (Cipher c, Curve d, Hash h)
               => ScrubbedBytes
               -> Maybe (KeyPair d)
               -> Maybe (KeyPair d)
               -> Maybe (PublicKey d)
               -> Maybe (PublicKey d)
               -> Maybe (Descriptor c d h ())
               -> HandshakeState c d h
handshakeState hn ls le rs re = maybe hs hs'
  where
    hs = HandshakeState (symmetricHandshake hn) ls le rs re
    hs' desc = snd . runIdentity $ runDescriptorT desc hs

writeHandshakeMsg :: (Cipher c, Curve d, Hash h)
                      => HandshakeState c d h
                      -> DescriptorIO c d h ByteString
                      -> Plaintext
                      -> IO (ByteString, HandshakeState c d h)
writeHandshakeMsg hs desc payload = do
  (d, hs') <- runDescriptorT desc hs
  let (ep, shs') = encryptAndHash payload $ hs' ^. hssSymmetricHandshake
      hs''       = hs' & hssSymmetricHandshake .~ shs'
  return (d `B.append` convert ep, hs'')

readHandshakeMsg :: (Cipher c, Curve d, Hash h)
                     => HandshakeState c d h
                     -> ByteString
                     -> (ByteString -> Descriptor c d h ByteString)
                     -> (Plaintext, HandshakeState c d h)
readHandshakeMsg hs buf desc = (dp, hs'')
  where
    (d, hs')   = runIdentity $ runDescriptorT (desc buf) hs
    (dp, shs') = decryptAndHash (cipherBytesToText (convert d))
                 $ hs' ^. hssSymmetricHandshake
    hs''       = hs' & hssSymmetricHandshake .~ shs'

writeHandshakeMsgFinal :: (Cipher c, Curve d, Hash h)
                       => HandshakeState c d h
                       -> DescriptorIO c d h ByteString
                       -> Plaintext
                       -> IO (ByteString, CipherState c, CipherState c)
writeHandshakeMsgFinal hs desc payload = do
  (d, hs') <- writeHandshakeMsg hs desc payload
  let (cs1, cs2) = split $ hs' ^. hssSymmetricHandshake
  return (d, cs1, cs2)

readHandshakeMsgFinal :: (Cipher c, Curve d, Hash h)
                      => HandshakeState c d h
                      -> ByteString
                      -> (ByteString -> Descriptor c d h ByteString)
                      -> (Plaintext, CipherState c, CipherState c)
readHandshakeMsgFinal hs buf desc = (pt, cs1, cs2)
  where
    (pt, hs')  = readHandshakeMsg hs buf desc
    (cs1, cs2) = split $ hs' ^. hssSymmetricHandshake

encryptPayload :: Cipher c
               => Plaintext
               -> CipherState c
               -> (ByteString, CipherState c)
encryptPayload pt cs = ((convert . cipherTextToBytes) ct, cs')
  where
    (ct, cs') = encryptAndIncrement ad pt cs
    ad = AssocData $ convert ("" :: ByteString)

decryptPayload :: Cipher c
               => ByteString
               -> CipherState c
               -> (Plaintext, CipherState c)
decryptPayload ct cs = (pt, cs')
  where
    (pt, cs') = decryptAndIncrement ad ((cipherBytesToText . convert) ct) cs
    ad = AssocData $ convert ("" :: ByteString)
