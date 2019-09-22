{-# LANGUAGE RankNTypes, ScopedTypeVariables #-}
------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.Handshake.Interpreter
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Internal.Handshake.Interpreter where

import Control.Applicative.Free
import Control.Exception.Safe
import Control.Lens
import Control.Monad.Coroutine.SuspensionFunctors
import Data.ByteArray (splitAt)
import Data.Maybe     (isJust)
import Data.Proxy
import Prelude hiding (splitAt)

import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Exception
import Crypto.Noise.Hash
import Crypto.Noise.Internal.Handshake.Pattern hiding (ss)
import Crypto.Noise.Internal.Handshake.State
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.SymmetricState

-- [ E ] -----------------------------------------------------------------------

interpretToken :: forall c d h r. (Cipher c, DH d, Hash h)
               => HandshakeRole
               -> Token r
               -> Handshake c d h r
interpretToken opRole (E next) = do
  myRole  <- use $ hsOpts . hoRole
  pskMode <- use hsPSKMode

  if opRole == myRole then do
    (_, pk) <- getKeyPair hoLocalEphemeral LocalEphemeral
    let pkBytes = dhPubToBytes pk

    if pskMode
      then hsSymmetricState %= mixKey pkBytes . mixHash pkBytes
      else hsSymmetricState %= mixHash pkBytes

    hsMsgBuffer      <>= pkBytes

  else do
    buf <- use hsMsgBuffer
    let (pkBytes, remainingBytes) = splitAt (dhLength (Proxy :: Proxy d)) buf
    theirKey <- maybe (throwM . InvalidKey $ RemoteEphemeral)
                      return
                      (dhBytesToPub pkBytes)
    hsOpts . hoRemoteEphemeral .= Just theirKey

    if pskMode
      then hsSymmetricState %= mixKey pkBytes . mixHash pkBytes
      else hsSymmetricState %= mixHash pkBytes

    hsMsgBuffer                .= remainingBytes

  return next

-- [ S ] -----------------------------------------------------------------------

interpretToken opRole (S next) = do
  myRole <- use $ hsOpts . hoRole

  if opRole == myRole then do
    ss <- use hsSymmetricState
    (_, pk) <- getKeyPair hoLocalStatic LocalStatic
    (ct, ss') <- encryptAndHash (dhPubToBytes pk) ss
    hsSymmetricState .= ss'
    hsMsgBuffer      <>= cipherTextToBytes ct

  else do
    configuredRemoteStatic <- use $ hsOpts . hoRemoteStatic
    if isJust configuredRemoteStatic
      then throwM StaticKeyOverwrite
      else do
        -- If a SymmetricKey has been established, the static key will be
        -- encrypted. In that case, the number of bytes to be read off the
        -- buffer will be the length of the public key plus a 16 byte
        -- authentication tag.
        k <- use $ hsSymmetricState . ssCipher . csk
        let dhLen     = dhLength (Proxy :: Proxy d)
            lenToRead = if isJust k then dhLen + 16 else dhLen

        buf <- use hsMsgBuffer
        ss  <- use hsSymmetricState
        let (b, rest) = splitAt lenToRead buf
        (pk, ss') <- decryptAndHash (cipherBytesToText b) ss
        pk' <- maybe (throwM . InvalidKey $ RemoteStatic)
                     return
                     (dhBytesToPub pk)

        hsOpts . hoRemoteStatic .= Just pk'
        hsSymmetricState        .= ss'
        hsMsgBuffer             .= rest

  return next

-- [ EE ] -----------------------------------------------------------------------

interpretToken _ (Ee next) = do
  ~(sk, _) <- getKeyPair   hoLocalEphemeral  LocalEphemeral
  rpk      <- getPublicKey hoRemoteEphemeral RemoteEphemeral
  hsSymmetricState %= mixKey (dhPerform sk rpk)

  return next

-- [ ES ] -----------------------------------------------------------------------

interpretToken _ (Es next) = do
  myRole <- use $ hsOpts . hoRole

  if myRole == InitiatorRole then do
    rpk      <- getPublicKey hoRemoteStatic   RemoteStatic
    ~(sk, _) <- getKeyPair   hoLocalEphemeral LocalEphemeral
    hsSymmetricState %= mixKey (dhPerform sk rpk)
  else do
    ~(sk, _) <- getKeyPair   hoLocalStatic     LocalStatic
    rpk      <- getPublicKey hoRemoteEphemeral RemoteEphemeral
    hsSymmetricState %= mixKey (dhPerform sk rpk)

  return next

-- [ SE ] -----------------------------------------------------------------------

interpretToken _ (Se next) = do
  myRole <- use $ hsOpts . hoRole

  if myRole == InitiatorRole then do
    ~(sk, _) <- getKeyPair   hoLocalStatic     LocalStatic
    rpk      <- getPublicKey hoRemoteEphemeral RemoteEphemeral
    hsSymmetricState %= mixKey (dhPerform sk rpk)
  else do
    rpk      <- getPublicKey hoRemoteStatic   RemoteStatic
    ~(sk, _) <- getKeyPair   hoLocalEphemeral LocalEphemeral
    hsSymmetricState %= mixKey (dhPerform sk rpk)

  return next

-- [ SS ] -----------------------------------------------------------------------

interpretToken _ (Ss next) = do
  ~(sk, _) <- getKeyPair   hoLocalStatic  LocalStatic
  rpk      <- getPublicKey hoRemoteStatic RemoteStatic
  hsSymmetricState %= mixKey (dhPerform sk rpk)

  return next

-- [ PSK ] -----------------------------------------------------------------------

interpretToken _ (Psk next) = do
  input <- Handshake <$> request $ HandshakeResultNeedPSK
  hsSymmetricState %= mixKeyAndHash input

  return next

processMsgPattern :: (Cipher c, DH d, Hash h)
                  => HandshakeRole
                  -> MessagePattern r
                  -> Handshake c d h r
processMsgPattern opRole mp = do
  myRole <- use $ hsOpts . hoRole
  buf    <- use hsMsgBuffer
  input  <- Handshake <$> request $ HandshakeResultMessage buf

  if opRole == myRole then do
    hsMsgBuffer .= mempty
    r  <- runAp (interpretToken opRole) mp
    ss <- use hsSymmetricState
    (encPayload, ss') <- encryptAndHash input ss
    hsMsgBuffer      <>= cipherTextToBytes encPayload
    hsSymmetricState .= ss'
    return r

  else do
    hsMsgBuffer .= input
    r         <- runAp (interpretToken opRole) mp
    remaining <- use hsMsgBuffer
    ss        <- use hsSymmetricState
    (decPayload, ss') <- decryptAndHash (cipherBytesToText remaining) ss
    hsMsgBuffer      .= decPayload
    hsSymmetricState .= ss'
    return r

interpretPreToken :: (Cipher c, DH d, Hash h)
                  => HandshakeRole
                  -> Token r
                  -> Handshake c d h r
interpretPreToken opRole (E next) = do
  myRole <- use $ hsOpts . hoRole
  pk <- if opRole == myRole
    then snd <$> getKeyPair hoLocalEphemeral LocalEphemeral
    else getPublicKey hoRemoteEphemeral RemoteEphemeral

  hsSymmetricState %= mixHash (dhPubToBytes pk)

  return next

interpretPreToken opRole (S next) = do
  myRole <- use $ hsOpts . hoRole
  pk <- if opRole == myRole
    then snd <$> getKeyPair hoLocalStatic LocalStatic
    else getPublicKey hoRemoteStatic RemoteStatic

  hsSymmetricState %= mixHash (dhPubToBytes pk)

  return next

interpretPreToken _ _ = throwM InvalidPattern

interpretMessage :: (Cipher c, DH d, Hash h)
                 => Message r
                 -> Handshake c d h r
interpretMessage (PreInitiator mp next) =
  runAp (interpretPreToken InitiatorRole) mp >> return next

interpretMessage (PreResponder mp next) =
  runAp (interpretPreToken ResponderRole) mp >> return next

interpretMessage (Initiator mp next) =
  processMsgPattern InitiatorRole mp >> return next

interpretMessage (Responder mp next) =
  processMsgPattern ResponderRole mp >> return next

runHandshakePattern :: (Cipher c, DH d, Hash h)
                    => HandshakePattern
                    -> Handshake c d h ()
runHandshakePattern hp = runAp interpretMessage $ hp ^. hpMsgSeq

getPublicKey :: Lens' (HandshakeOpts d) (Maybe (PublicKey d))
             -> ExceptionKeyType
             -> Handshake c d h (PublicKey d)
getPublicKey k keyType = do
  r <- use $ hsOpts . k
  maybe (throwM . KeyMissing $ keyType) return r

getKeyPair :: Lens' (HandshakeOpts d) (Maybe (KeyPair d))
           -> ExceptionKeyType
           -> Handshake c d h (KeyPair d)
getKeyPair k keyType = do
  r <- use $ hsOpts . k
  maybe (throwM . KeyMissing $ keyType) return r
