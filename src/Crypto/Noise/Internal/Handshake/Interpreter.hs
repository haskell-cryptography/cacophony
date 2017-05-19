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
import Data.Monoid    ((<>))
import Data.Proxy
import Prelude hiding (splitAt)

import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash
import Crypto.Noise.Internal.Handshake.Pattern hiding (e, s, ee, es, se, ss)
import Crypto.Noise.Internal.Handshake.State
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.SymmetricState
import Crypto.Noise.Internal.Types

-- [ E ] -----------------------------------------------------------------------

interpretToken :: forall c d h r. (Cipher c, DH d, Hash h)
               => HandshakeRole
               -> Token r
               -> Handshake c d h r
interpretToken opRole (E next) = do
  myRole  <- use $ hsOpts . hoRole
  pskMode <- use hsPSKMode

  if opRole == myRole then do
    (_, pk) <- getKeyPair hoLocalEphemeral "local ephemeral"
    let pkBytes = dhPubToBytes pk

    if pskMode
      then hsSymmetricState %= mixKey pkBytes . mixHash pkBytes
      else hsSymmetricState %= mixHash pkBytes

    hsMsgBuffer      <>= pkBytes

  else do
    buf <- use hsMsgBuffer
    let (pkBytes, remainingBytes) = splitAt (dhLength (Proxy :: Proxy d)) buf
    theirKey <- maybe (throwM . HandshakeError $ "invalid remote ephemeral key")
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
    (_, pk) <- getKeyPair hoLocalStatic "local static"
    (ct, ss') <- encryptAndHash (dhPubToBytes pk) ss
    hsSymmetricState .= mixHash (cipherTextToBytes ct) ss'
    hsMsgBuffer      <>= cipherTextToBytes ct

  else do
    configuredRemoteStatic <- use $ hsOpts . hoRemoteStatic
    if isJust configuredRemoteStatic
      then throwM . InvalidHandshakeOptions $ "unable to overwrite remote static key"
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
        (pk, ss') <- maybe (throwM . HandshakeError $ "failed to decrypt remote static key")
                           return
                           (decryptAndHash (cipherBytesToText b) ss)
        pk' <- maybe (throwM . HandshakeError $ "invalid static key provided by remote peer")
                     return
                     (dhBytesToPub pk)

        hsOpts . hoRemoteStatic .= Just pk'
        hsSymmetricState        .= ss'
        hsMsgBuffer             .= rest

  return next

-- [ EE ] -----------------------------------------------------------------------

interpretToken _ (Ee next) = do
  ~(sk, _) <- getKeyPair   hoLocalEphemeral  "local ephemeral"
  rpk      <- getPublicKey hoRemoteEphemeral "remote ephemeral"
  hsSymmetricState %= mixKey (dhPerform sk rpk)

  return next

-- [ ES ] -----------------------------------------------------------------------

interpretToken _ (Es next) = do
  myRole <- use $ hsOpts . hoRole

  if myRole == InitiatorRole then do
    rpk      <- getPublicKey hoRemoteStatic   "remote static"
    ~(sk, _) <- getKeyPair   hoLocalEphemeral "local ephemeral"
    hsSymmetricState %= mixKey (dhPerform sk rpk)
  else do
    ~(sk, _) <- getKeyPair   hoLocalStatic     "local static"
    rpk      <- getPublicKey hoRemoteEphemeral "remote ephemeral"
    hsSymmetricState %= mixKey (dhPerform sk rpk)

  return next

-- [ SE ] -----------------------------------------------------------------------

interpretToken _ (Se next) = do
  myRole <- use $ hsOpts . hoRole

  if myRole == InitiatorRole then do
    ~(sk, _) <- getKeyPair   hoLocalStatic     "local static"
    rpk      <- getPublicKey hoRemoteEphemeral "remote ephemeral"
    hsSymmetricState %= mixKey (dhPerform sk rpk)
  else do
    rpk      <- getPublicKey hoRemoteStatic   "remote static"
    ~(sk, _) <- getKeyPair   hoLocalEphemeral "local ephemeral"
    hsSymmetricState %= mixKey (dhPerform sk rpk)

  return next

-- [ SS ] -----------------------------------------------------------------------

interpretToken _ (Ss next) = do
  ~(sk, _) <- getKeyPair   hoLocalStatic  "local static"
  rpk      <- getPublicKey hoRemoteStatic "remote static"
  hsSymmetricState %= mixKey (dhPerform sk rpk)

  return next

-- [ PSK ] -----------------------------------------------------------------------

interpretToken _ (Psk next) = do
  input <- Handshake <$> request $ NeedPSK
  hsSymmetricState %= mixKeyAndHash input

  return next

processMsgPattern :: (Cipher c, DH d, Hash h)
                  => HandshakeRole
                  -> MessagePattern r
                  -> Handshake c d h r
processMsgPattern opRole mp = do
  myRole <- use $ hsOpts . hoRole
  buf    <- use hsMsgBuffer
  input  <- Handshake <$> request $ Message buf

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
    then snd <$> getKeyPair hoLocalEphemeral "local ephemeral"
    else getPublicKey hoRemoteEphemeral "remote ephemeral"

  hsSymmetricState %= mixHash (dhPubToBytes pk)

  return next

interpretPreToken opRole (S next) = do
  myRole <- use $ hsOpts . hoRole
  pk <- if opRole == myRole
    then snd <$> getKeyPair hoLocalStatic "local static"
    else getPublicKey hoRemoteStatic "remote static"

  hsSymmetricState %= mixHash (dhPubToBytes pk)

  return next

interpretPreToken _ _ = throwM . HandshakeError $ "invalid pre-message pattern token"

interpretMessage :: (Cipher c, DH d, Hash h)
                 => Message r
                 -> Handshake c d h r
interpretMessage (PreInitiator mp next) = do
  runAp (interpretPreToken InitiatorRole) mp
  return next

interpretMessage (PreResponder mp next) = do
  runAp (interpretPreToken ResponderRole) mp
  return next

interpretMessage (Initiator mp next) =
  processMsgPattern InitiatorRole mp >> return next

interpretMessage (Responder mp next) =
  processMsgPattern ResponderRole mp >> return next

runHandshakePattern :: (Cipher c, DH d, Hash h)
                    => HandshakePattern
                    -> Handshake c d h ()
runHandshakePattern hp = runAp interpretMessage $ hp ^. hpMsgSeq

getPublicKey :: Lens' (HandshakeOpts d) (Maybe (PublicKey d))
             -> String
             -> Handshake c d h (PublicKey d)
getPublicKey k desc = do
  r <- use $ hsOpts . k
  maybe (throwM (InvalidHandshakeOptions $ "a " <> desc <> " key is required but has not been set"))
        return
        r

getKeyPair :: Lens' (HandshakeOpts d) (Maybe (KeyPair d))
           -> String
           -> Handshake c d h (KeyPair d)
getKeyPair k desc = do
  r <- use $ hsOpts . k
  maybe (throwM (InvalidHandshakeOptions $ "a " <> desc <> " key is required but has not been set"))
        return
        r
