{-# LANGUAGE OverloadedStrings, FlexibleInstances,
    GeneralizedNewtypeDeriving, TemplateHaskell,
    RankNTypes, FlexibleContexts #-}
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

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.SymmetricHandshakeState
import Crypto.Noise.Types

data HandshakeState c d =
  HandshakeState { _hssSymmetricHandshake :: SymmetricHandshakeState c
                 , _hssLocalStaticKey     :: Maybe (KeyPair d)
                 , _hssLocalEphemeralKey  :: Maybe (KeyPair d)
                 , _hssRemoteStaticKey    :: Maybe (PublicKey d)
                 , _hssRemoteEphemeralKey :: Maybe (PublicKey d)
                 }

$(makeLenses ''HandshakeState)

newtype DescriptorT c d m a = DescriptorT { unD :: StateT (HandshakeState c d) m a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadState(HandshakeState c d))

type Descriptor c d a = DescriptorT c d Identity a

type DescriptorIO c d a = DescriptorT c d IO a

runDescriptorT :: Monad m => DescriptorT c d m a -> HandshakeState c d -> m (a, HandshakeState c d)
runDescriptorT = runStateT . unD

class Monad m => MonadHandshake m where
  tokenPreWS :: m ()
  tokenPreRS :: m ()
  tokenPreWE :: m ()
  tokenPreRE :: m ()
  tokenRE   :: ByteString -> m ByteString
  tokenRS   :: ByteString -> m ByteString
  tokenWE   :: MonadIO m => m ByteString
  tokenWS   :: m ByteString
  tokenDHEE :: m ()
  tokenDHES :: m ()
  tokenDHSE :: m ()
  tokenDHSS :: m ()

instance (Monad m, Cipher c, Curve d) => MonadHandshake (DescriptorT c d m) where
  tokenPreWS = tokenPreWX hssLocalStaticKey

  tokenPreRS = tokenPreRX hssRemoteStaticKey

  tokenPreWE = tokenPreWX hssLocalEphemeralKey

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

getLocalStaticKey :: (Cipher c, Curve d) => HandshakeState c d -> KeyPair d
getLocalStaticKey hs = fromMaybe (error "local static key not set")
                                 (hs ^. hssLocalStaticKey)

getLocalEphemeralKey :: (Cipher c, Curve d) => HandshakeState c d -> KeyPair d
getLocalEphemeralKey hs = fromMaybe (error "local ephemeral key not set")
                                    (hs ^. hssLocalEphemeralKey)

getRemoteStaticKey :: (Cipher c, Curve d) => HandshakeState c d -> PublicKey d
getRemoteStaticKey hs = fromMaybe (error "remote static key not set")
                                  (hs ^. hssRemoteStaticKey)

getRemoteEphemeralKey :: (Cipher c, Curve d) => HandshakeState c d -> PublicKey d
getRemoteEphemeralKey hs = fromMaybe (error "remote ephemeral key not set")
                                     (hs ^. hssRemoteEphemeralKey)

tokenPreWX :: (MonadState (HandshakeState c d) m, Cipher c, Curve d)
           => Lens' (HandshakeState c d) (Maybe (KeyPair d))
           -> m ()
tokenPreWX keyToView = do
  hs <- get
  let shs     = hs ^. hssSymmetricHandshake
      (_, pk) = fromMaybe (error "tokenPreIX: local key not set") (hs ^. keyToView)
      shs'    = mixHash (curvePubToBytes pk) shs
  put $ hs & hssSymmetricHandshake .~ shs'

tokenPreRX :: (MonadState (HandshakeState c d) m, Cipher c, Curve d)
           => Lens' (HandshakeState c d) (Maybe (PublicKey d))
           -> m ()
tokenPreRX keyToView = do
  hs <- get
  let shs  = hs ^. hssSymmetricHandshake
      pk   = fromMaybe (error "tokenPreRX: remote key not set") (hs ^. keyToView)
      shs' = mixHash (curvePubToBytes pk) shs
  put $ hs & hssSymmetricHandshake .~ shs'

tokenRX :: (MonadState (HandshakeState c d) m, Cipher c, Curve d)
       => ByteString
       -> Lens' (HandshakeState c d) (Maybe (PublicKey d))
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
    d hk
      | hk        = 32 + 16
      | otherwise = 32 -- this should call curveLen!

handshakeState :: (Cipher c, Curve d)
               => ScrubbedBytes
               -> Maybe (KeyPair d)
               -> Maybe (KeyPair d)
               -> Maybe (PublicKey d)
               -> Maybe (PublicKey d)
               -> Maybe (Descriptor c d ())
               -> HandshakeState c d
handshakeState hn ls le rs re = maybe hs hs'
  where
    hs = HandshakeState (symmetricHandshake hn) ls le rs re
    hs' desc = snd . runIdentity $ runDescriptorT desc hs

writeHandshakeMsg :: (Cipher c, Curve d)
                      => HandshakeState c d
                      -> DescriptorIO c d ByteString
                      -> Plaintext
                      -> IO (ByteString, HandshakeState c d)
writeHandshakeMsg hs desc payload = do
  (d, hs') <- runDescriptorT desc hs
  let (ep, shs') = encryptAndHash payload $ hs' ^. hssSymmetricHandshake
      hs''       = hs' & hssSymmetricHandshake .~ shs'
  return (d `B.append` convert ep, hs'')

readHandshakeMsg :: (Cipher c, Curve d)
                     => HandshakeState c d
                     -> ByteString
                     -> (ByteString -> Descriptor c d ByteString)
                     -> (Plaintext, HandshakeState c d)
readHandshakeMsg hs buf desc = (dp, hs'')
  where
    (d, hs')   = runIdentity $ runDescriptorT (desc buf) hs
    (dp, shs') = decryptAndHash (cipherBytesToText (convert d))
                 $ hs' ^. hssSymmetricHandshake
    hs''       = hs' & hssSymmetricHandshake .~ shs'

writeHandshakeMsgFinal :: (Cipher c, Curve d)
                       => HandshakeState c d
                       -> DescriptorIO c d ByteString
                       -> Plaintext
                       -> IO (ByteString, CipherState c, CipherState c)
writeHandshakeMsgFinal hs desc payload = do
  (d, hs') <- writeHandshakeMsg hs desc payload
  let (cs1, cs2) = split $ hs' ^. hssSymmetricHandshake
  return (d, cs1, cs2)

readHandshakeMsgFinal :: (Cipher c, Curve d)
                      => HandshakeState c d
                      -> ByteString
                      -> (ByteString -> Descriptor c d ByteString)
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
