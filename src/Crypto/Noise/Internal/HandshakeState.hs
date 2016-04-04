{-# LANGUAGE OverloadedStrings, FlexibleInstances,
    GeneralizedNewtypeDeriving, TemplateHaskell,
    RankNTypes, FlexibleContexts, ScopedTypeVariables,
    RecordWildCards #-}
{-# OPTIONS_HADDOCK hide #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.HandshakeState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.HandshakeState
  ( -- * Types
    HandshakeCallbacks(..),
    HandshakeState,
    HandshakeStateParams(..),
    SendingCipherState,
    ReceivingCipherState,
    -- * Functions
    handshakeState,
    runHandshake,
    evalHandshakePattern,
    evalToken,
    encryptPayload,
    decryptPayload
  ) where

import Control.Exception (throw)
import Control.Lens hiding (re)
import Control.Monad.Free.Church
import Control.Monad.State
import Data.ByteString (ByteString)
import qualified Data.ByteString as B (empty, splitAt)
import Data.Maybe (fromMaybe, isJust)
import Data.Proxy

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.SymmetricState
import Crypto.Noise.Internal.HandshakePattern hiding (s, split)
import Crypto.Noise.Types

-- | Contains the parameters required to initialize a 'HandshakeState'.
--   The keys you need to provide are dependent on the type of handshake
--   you are using. If you fail to provide a key that your handshake
--   type depends on, or you provide a static key which is supposed to
--   be set during the exchange, you will receive a
--   'HandshakeStateFailure' exception.
data HandshakeStateParams c d =
  HandshakeStateParams { hspPattern            :: HandshakePattern c
                       , hspPrologue           :: Plaintext
                       , hspPreSharedKey       :: Maybe Plaintext
                       , hspLocalStaticKey     :: Maybe (KeyPair d)
                       , hspLocalEphemeralKey  :: Maybe (KeyPair d)
                       , hspRemoteStaticKey    :: Maybe (PublicKey d)
                       , hspRemoteEphemeralKey :: Maybe (PublicKey d)
                       , hspInitiator          :: Bool
                       }

-- | Represents the state of a handshake.
data HandshakeState c d h =
  HandshakeState { _hsSymmetricState     :: SymmetricState c h
                 , _hsLocalStaticKey     :: Maybe (KeyPair d)
                 , _hsLocalEphemeralKey  :: Maybe (KeyPair d)
                 , _hsRemoteStaticKey    :: Maybe (PublicKey d)
                 , _hsRemoteEphemeralKey :: Maybe (PublicKey d)
                 , _hsInitiator          :: Bool
                 , _hsMsgBuffer          :: ByteString
                 , _hsPattern            :: HandshakePattern c
                 }

-- | Contains the callbacks required by 'runHandshake'.
--
--   'hscbSend' and 'hscbRecv' are called when handshake data needs to be sent
--   to and received from the remote peer, respectively. 'hscbSend' will
--   typically be a function which writes to a socket, and 'hscbRecv' will
--   typically be a function which reads from a socket.
--
--   'hscbPayloadIn' and 'hscbPayloadOut' are called when handshake payloads
--   are received and sent, respectively. To be more precise, 'hscbPayloadIn'
--   is called after an incoming handshake message has been decrypted
--   successfully, and 'hscbPayloadOut' is called during the construction of
--   an outgoing handshake message.
--
--   'hscbStaticIn' is called as soon as a static key is received from the
--   remote party. If this function evaluates to @False@, the handshake is
--   immediately aborted and a 'HandshakeAborted' exception is thrown.
--   Otherwise, the handshake proceeds normally. This is intended to create
--   a firewall/access control list which can be used to prohibit
--   communication with certain parties. In the
--   'Crypto.Noise.HandshakePatterns.noiseXR' and
--   'Crypto.Noise.HandshakePatterns.noiseIX' patterns, this will prevent the
--   initiator from discovering your identity. In the
--   'Crypto.Noise.HandshakePatterns.noiseXX' pattern, this will prevent the
--   responder from discovering your identity.
--
--   All five of these callbacks apply to handshake messages only. After the
--   handshake is complete they are no longer used.
data HandshakeCallbacks d =
  HandshakeCallbacks { hscbSend       :: ByteString -> IO ()
                     , hscbRecv       :: IO ByteString
                     , hscbPayloadIn  :: Plaintext -> IO ()
                     , hscbPayloadOut :: IO Plaintext
                     , hscbStaticIn   :: PublicKey d -> IO Bool
                     }

type HandshakeMonad c d h = StateT (HandshakeState c d h) IO
type PreMsgMonad    c d h = StateT (HandshakeState c d h) Identity

-- | Represents the Noise cipher state for outgoing data.
newtype SendingCipherState   c = SCS { _unSCS :: CipherState c }

-- | Represents the Noise cipher state for incoming data.
newtype ReceivingCipherState c = RCS { _unRCS :: CipherState c }

$(makeLenses ''HandshakeState)

-- | Constructs a 'HandshakeState'.
handshakeState :: forall c d h. (Cipher c, Curve d, Hash h)
               => HandshakeStateParams c d
               -> HandshakeState c d h
handshakeState HandshakeStateParams{..} =
  maybe hs'' hs''' $ hspPattern ^. hpPreActions
  where
    ss        = symmetricState $ mkHPN hs (hspPattern ^. hpName) (isJust hspPreSharedKey)
    hs        = HandshakeState ss
                               hspLocalStaticKey
                               hspLocalEphemeralKey
                               hspRemoteStaticKey
                               hspRemoteEphemeralKey
                               hspInitiator
                               ""
                               hspPattern
    hs'       = doPrologue hspPrologue hs
    hs''      = maybe hs' (`doPSK` hs') hspPreSharedKey
    hs''' pmp = runIdentity . execStateT (iterM evalPreMsgPattern pmp) $ hs''

doPrologue :: forall c d h. (Cipher c, Curve d, Hash h)
           => Plaintext
           -> HandshakeState c d h
           -> HandshakeState c d h
doPrologue (Plaintext pro) hs = hs & hsSymmetricState %~ mixHash pro

doPSK :: forall c d h. (Cipher c, Curve d, Hash h)
      => Plaintext
      -> HandshakeState c d h
      -> HandshakeState c d h
doPSK (Plaintext psk) hs = hs & hsSymmetricState %~ mixPSK psk

mkHPN :: forall c d h. (Cipher c, Curve d, Hash h)
      => HandshakeState c d h
      -> ByteString
      -> Bool
      -> ScrubbedBytes
mkHPN _ hpn psk = if psk then hpn' ppsk else hpn' p
  where
    p        = bsToSB' "Noise_"
    ppsk     = bsToSB' "NoisePSK_"
    a        = curveName  (Proxy :: Proxy d)
    b        = cipherName (Proxy :: Proxy c)
    c        = hashName   (Proxy :: Proxy h)
    u        = bsToSB' "_"
    hpn' pfx = concatSB [pfx, bsToSB' hpn, u, a, u, b, u, c]

-- | Given a 'HandshakeState' and 'HandshakeCallbacks', runs a handshake
--   from start to finish. The 'SendingCipherState' and
--   'ReceivingCipherState' are intended to be used by 'encryptPayload'
--   and 'decryptPayload', respectively.
runHandshake :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> HandshakeCallbacks d
             -> IO (SendingCipherState c, ReceivingCipherState c)
runHandshake hs hscb = do
  (cs1, cs2) <- evalStateT p hs
  if hs ^. hsInitiator then
    return (SCS cs1, RCS cs2)
  else
    return (SCS cs2, RCS cs1)

  where
    p = iterM (evalHandshakePattern hscb) (hs ^. hsPattern ^. hpActions)

evalHandshakePattern :: (Cipher c, Curve d, Hash h)
                     => HandshakeCallbacks d
                     -> HandshakePatternF (HandshakeMonad c d h (CipherState c, CipherState c))
                     -> HandshakeMonad c d h (CipherState c, CipherState c)
evalHandshakePattern hscb p = do
  hs <- get

  case p of
    Initiator t next -> sendOrRecv hs True t next
    Responder t next -> sendOrRecv hs False t next
    Split            -> return . split $ hs ^. hsSymmetricState

  where
    sendOrRecv hs i t next = do
      if i == hs ^. hsInitiator then do
        iterM (evalToken hscb i) t
        hs' <- get
        payload <- liftIO $ hscbPayloadOut hscb
        let (ep, ss) = encryptAndHash payload $ hs' ^. hsSymmetricState
            toSend   = (hs' ^. hsMsgBuffer) `mappend` sbToBS' ep
        liftIO . hscbSend hscb $ toSend
        put $ hs' & hsMsgBuffer      .~ B.empty
                  & hsSymmetricState .~ ss
      else do
        msg <- liftIO $ hscbRecv hscb
        put $ hs & hsMsgBuffer .~ msg
        iterM (evalToken hscb i) t
        hs' <- get
        let remaining = hs' ^. hsMsgBuffer
            (dp, ss)  = decryptAndHash (cipherBytesToText (bsToSB' remaining))
                        $ hs' ^. hsSymmetricState
        liftIO . hscbPayloadIn hscb $ dp
        put $ hs' & hsMsgBuffer      .~ B.empty
                  & hsSymmetricState .~ ss
      next

evalToken :: forall c d h. (Cipher c, Curve d, Hash h)
          => HandshakeCallbacks d
          -> Bool
          -> TokenF (HandshakeMonad c d h ())
          -> HandshakeMonad c d h ()
evalToken _ i (E next) = do
  hs <- get

  if i == hs ^. hsInitiator then do
    ~kp@(_, pk) <- liftIO curveGenKey
    let pk'  = curvePubToBytes pk
        ss   = hs ^. hsSymmetricState
        ss'  = mixHash pk' ss
        ss'' = if ss' ^. ssHasPSK then mixKey pk' ss' else ss'
    put $ hs & hsLocalEphemeralKey .~ Just kp
             & hsSymmetricState    .~ ss''
             & hsMsgBuffer         %~ (flip mappend . convert) pk'
  else do
    let (b, rest) = B.splitAt (curveLength (Proxy :: Proxy d)) $ hs ^. hsMsgBuffer
        reBytes   = convert b
        ss        = hs ^. hsSymmetricState
        ss'       = mixHash reBytes ss
        ss''      = if ss ^. ssHasPSK then mixKey reBytes ss' else ss'
    put $ hs & hsRemoteEphemeralKey .~ Just (curveBytesToPub reBytes)
             & hsSymmetricState     .~ ss''
             & hsMsgBuffer          .~ rest
  next

evalToken hscb i (S next) = do
  hs <- get

  if i == hs ^. hsInitiator then do
    let pk        = curvePubToBytes . snd . getLocalStaticKey $ hs
        ss        = hs ^. hsSymmetricState
        (ct, ss') = encryptAndHash ((Plaintext . convert) pk) ss
    put $ hs & hsSymmetricState .~ ss'
             & hsMsgBuffer      %~ (flip mappend . convert) ct
  else
    if isJust (hs ^. hsRemoteStaticKey) then
      throw . HandshakeStateFailure $ "unable to overwrite remote static key"
    else do
      let hasKey    = hs ^. hsSymmetricState . ssHasKey
          len       = curveLength (Proxy :: Proxy d)
          -- The magic 16 here represents the length of the auth tag.
          d         = if hasKey then len + 16 else len
          (b, rest) = B.splitAt d $ hs ^. hsMsgBuffer
          ct        = cipherBytesToText . convert $ b
          ss        = hs ^. hsSymmetricState
          (Plaintext pt, ss') = decryptAndHash ct ss
          theirKey  = curveBytesToPub pt

      proceed <- liftIO . hscbStaticIn hscb $ theirKey
      if proceed then
        put $ hs & hsRemoteStaticKey .~ Just theirKey
                 & hsSymmetricState  .~ ss'
                 & hsMsgBuffer       .~ rest
      else
        throw . HandshakeAborted $ "handshake aborted by user"

  next

evalToken _ _ (Dhee next) = do
  hs <- get

  let ss       = hs ^. hsSymmetricState
      ~(sk, _) = getLocalEphemeralKey hs
      rpk      = getRemoteEphemeralKey hs
      dh       = curveDH sk rpk
      ss'      = mixKey dh ss

  put $ hs & hsSymmetricState .~ ss'

  next

evalToken _ i (Dhes next) = do
  hs <- get

  if i == hs ^. hsInitiator then do
    let ss       = hs ^. hsSymmetricState
        ~(sk, _) = getLocalEphemeralKey hs
        rpk      = getRemoteStaticKey hs
        dh       = curveDH sk rpk
        ss'      = mixKey dh ss
    put $ hs & hsSymmetricState .~ ss'
    next
  else
    evalToken undefined (not i) $ Dhse next

evalToken _ i (Dhse next) = do
  hs <- get

  if i == hs ^. hsInitiator then do
    let ss       = hs ^. hsSymmetricState
        ~(sk, _) = getLocalStaticKey hs
        rpk      = getRemoteEphemeralKey hs
        dh       = curveDH sk rpk
        ss'      = mixKey dh ss
    put $ hs & hsSymmetricState .~ ss'
    next
  else
    evalToken undefined (not i) $ Dhes next

evalToken _ _ (Dhss next) = do
  hs <- get

  let ss       = hs ^. hsSymmetricState
      ~(sk, _) = getLocalStaticKey hs
      rpk      = getRemoteStaticKey hs
      dh       = curveDH sk rpk
      ss'      = mixKey dh ss
  put $ hs & hsSymmetricState .~ ss'

  next

evalPreMsgPattern :: forall c d h. (Cipher c, Curve d, Hash h)
                  => HandshakePatternF (PreMsgMonad c d h ())
                  -> PreMsgMonad c d h ()
evalPreMsgPattern (Initiator t next) = do
  iterM (evalPreMsgToken True) t
  next

evalPreMsgPattern (Responder t next) = do
  iterM (evalPreMsgToken False) t
  next

evalPreMsgPattern _ = error "invalid pre-message pattern operation"

evalPreMsgToken :: forall c d h. (Cipher c, Curve d, Hash h)
                => Bool
                -> TokenF (PreMsgMonad c d h ())
                -> PreMsgMonad c d h ()
evalPreMsgToken i (E next) = do
  hs <- get

  let ss  = hs ^. hsSymmetricState
      pk  = if i == hs ^. hsInitiator then (snd . getLocalEphemeralKey) hs else getRemoteEphemeralKey hs
      ss' = mixHash (curvePubToBytes pk) ss
  put $ hs & hsSymmetricState .~ ss'

  next

evalPreMsgToken i (S next) = do
  hs <- get

  let ss  = hs ^. hsSymmetricState
      pk  = if i == hs ^. hsInitiator then (snd . getLocalStaticKey) hs else getRemoteStaticKey hs
      ss' = mixHash (curvePubToBytes pk) ss
  put $ hs & hsSymmetricState .~ ss'

  next

evalPreMsgToken _ _ = error "invalid pre-message pattern token"

getLocalStaticKey :: Curve d => HandshakeState c d h -> KeyPair d
getLocalStaticKey hs = fromMaybe (throw (HandshakeStateFailure "local static key not set"))
                                 (hs ^. hsLocalStaticKey)

getLocalEphemeralKey :: Curve d => HandshakeState c d h -> KeyPair d
getLocalEphemeralKey hs = fromMaybe (throw (HandshakeStateFailure "local ephemeral key not set"))
                                    (hs ^. hsLocalEphemeralKey)

getRemoteStaticKey :: Curve d => HandshakeState c d h -> PublicKey d
getRemoteStaticKey hs = fromMaybe (throw (HandshakeStateFailure "remote static key not set"))
                                  (hs ^. hsRemoteStaticKey)

getRemoteEphemeralKey :: Curve d => HandshakeState c d h -> PublicKey d
getRemoteEphemeralKey hs = fromMaybe (throw (HandshakeStateFailure "remote ephemeral key not set"))
                                     (hs ^. hsRemoteEphemeralKey)

-- | Encrypts a payload. The returned 'SendingCipherState' must be used
--   for all subsequent calls.
encryptPayload :: Cipher c
               => Plaintext
               -- ^ The data to encrypt
               -> SendingCipherState c
               -> (ByteString, SendingCipherState c)
encryptPayload pt (SCS cs) = ((convert . cipherTextToBytes) ct, SCS cs')
  where
    (ct, cs') = encryptAndIncrement ad pt cs
    ad = AssocData . bsToSB' $ ""

-- | Decrypts a payload. The returned 'ReceivingCipherState' must be used
--   for all subsequent calls.
decryptPayload :: Cipher c
               => ByteString
               -- ^ The data to decrypt
               -> ReceivingCipherState c
               -> (Plaintext, ReceivingCipherState c)
decryptPayload ct (RCS cs) = (pt, RCS cs')
  where
    (pt, cs') = decryptAndIncrement ad ((cipherBytesToText . convert) ct) cs
    ad = AssocData . bsToSB' $ ""
