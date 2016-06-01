{-# LANGUAGE OverloadedStrings, TemplateHaskell, ScopedTypeVariables #-}
{-# OPTIONS_HADDOCK hide #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.NoiseState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.NoiseState where

import Control.Monad.Coroutine
import Control.Monad.Coroutine.SuspensionFunctors
import Control.Monad.Except (MonadError(..), runExcept)
import Control.Monad.State  (MonadState(..), runStateT, get, put)
import Control.Monad.Trans.Free.Church
import Control.Lens
import Data.ByteString      (ByteString)
import Data.Maybe           (isJust)
import Data.Monoid          ((<>))
import Data.Proxy           (Proxy(..))
import Prelude hiding       (concat, splitAt, length)

import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.SymmetricState
import Crypto.Noise.Internal.Handshake
import Crypto.Noise.Internal.HandshakePattern
import Crypto.Noise.Internal.Types
import Data.ByteArray.Extend

-- | Represents the complete state of a Noise conversation.
data NoiseState c d h =
  NoiseState { _nsHandshakeState       :: HandshakeState c d h
             , _nsHandshakeSuspension  :: ScrubbedBytes -> Handshake c d h ()
             , _nsSendingCipherState   :: Maybe (CipherState c)
             , _nsReceivingCipherState :: Maybe (CipherState c)
             }

$(makeLenses ''NoiseState)

-- | Returns a default set of handshake options. The prologue is set to an
--   empty string, PSK-mode is disabled, and all keys are set to 'Nothing'.
defaultHandshakeOpts :: HandshakePattern
                     -> HandshakeRole
                     -> HandshakeOpts d
defaultHandshakeOpts hp r =
  HandshakeOpts { _hoPattern             = hp
                , _hoRole                = r
                , _hoPrologue            = ""
                , _hoPreSharedKey        = Nothing
                , _hoLocalStatic         = Nothing
                , _hoLocalSemiEphemeral  = Nothing
                , _hoLocalEphemeral      = Nothing
                , _hoRemoteStatic        = Nothing
                , _hoRemoteSemiEphemeral = Nothing
                , _hoRemoteEphemeral     = Nothing
                }

mkHandshakeName :: forall c d h proxy. (Cipher c, DH d, Hash h)
                => ByteString
                -> Bool
                -> proxy (c, d, h)
                -> ScrubbedBytes
mkHandshakeName hpn psk _ = p <> convert hpn <> "_" <> d <> "_" <> c <> "_" <> h
  where
    p = if psk then "NoisePSK_" else "Noise_"
    c = cipherName (Proxy :: Proxy c)
    d = dhName     (Proxy :: Proxy d)
    h = hashName   (Proxy :: Proxy h)

invertRole :: HandshakeRole -> HandshakeRole
invertRole InitiatorRole = ResponderRole
invertRole ResponderRole = InitiatorRole

handshakeState :: forall c d h. (Cipher c, DH d, Hash h)
               => HandshakeOpts d
               -> HandshakeState c d h
handshakeState ho | not (validPSK (ho ^. hoPreSharedKey)) = error "pre-shared key must be 32 bytes in length"
                  | otherwise =
  HandshakeState { _hsSymmetricState = ss''
                 , _hsOpts           = ho
                 , _hsMsgBuffer      = mempty
                 }
  where
    validPSK = maybe True (\psk -> length psk == 32)
    ss   = symmetricState $ mkHandshakeName (ho ^. hoPattern ^. hpName)
                                            (isJust (ho ^. hoPreSharedKey))
                                            (Proxy :: Proxy (c, d, h))

    ss'  = mixHash (ho ^. hoPrologue) ss
    ss'' = maybe ss' (`mixPSK` ss') $ ho ^. hoPreSharedKey

runHandshake :: (Cipher c, Hash h)
             => ScrubbedBytes
             -> NoiseState c d h
             -> Either NoiseException (ScrubbedBytes, NoiseState c d h)
runHandshake msg ns = runExcept $ do
  ((res, ns''), hs') <- runStateT st $ ns ^. nsHandshakeState
  return (res, ns'' & nsHandshakeState .~ hs')

  where
    st = do
      x <- resume . runHandshake' . (ns ^. nsHandshakeSuspension) $ msg
      case x of
        Left (Request req resp) -> return (req, ns & nsHandshakeSuspension .~ (Handshake . resp))
        Right _ -> do
          hs <- get

          let (cs1, cs2) = split (hs ^. hsSymmetricState)
              ns'        = if hs ^. hsOpts . hoRole == InitiatorRole
                             then ns & nsSendingCipherState   .~ Just cs1
                                     & nsReceivingCipherState .~ Just cs2
                             else ns & nsSendingCipherState   .~ Just cs2
                                     & nsReceivingCipherState .~ Just cs1
          return (hs ^. hsMsgBuffer, ns')

-- | Creates a 'NoiseState'.
noiseState :: forall c d h. (Cipher c, DH d, Hash h)
           => HandshakeOpts d
           -> NoiseState c d h
noiseState ho =
  NoiseState { _nsHandshakeState       = hs''
             , _nsHandshakeSuspension  = suspension
             , _nsSendingCipherState   = Nothing
             , _nsReceivingCipherState = Nothing
             }

  where
    hs        = handshakeState ho :: HandshakeState c d h
    coroutine = iterM evalPattern $ hoistFT (return . runIdentity) (ho ^. hoPattern . hpActions)
    (suspension, hs'') = case runExcept (runStateT (resume (runHandshake' coroutine)) hs) of
            Left err -> error $ "handshake pattern interpreter threw exception: " <> show err
            Right result -> case result of
              (Left (Request _ resp), hs') -> (Handshake . resp, hs')
              _ -> error "handshake pattern interpreter ended pre-maturely"

processPatternOp :: (Cipher c, DH d, Hash h)
                 => HandshakeRole
                 -> FT TokenF Identity ()
                 -> Handshake c d h ()
                 -> Handshake c d h ()
processPatternOp opRole t next = do
  hs <- get
  input <- Handshake <$> request $ hs ^. hsMsgBuffer
  hs' <- get

  if opRole == hs' ^. hsOpts . hoRole then do
    put $ hs' & hsMsgBuffer .~ mempty
    iterM (evalMsgToken opRole) $ hoistFT (return . runIdentity) t

    hs'' <- get

    let enc = encryptAndHash (convert input) $ hs'' ^. hsSymmetricState

    (ep, ss) <- either throwError return enc

    put $ hs'' & hsMsgBuffer      %~ (flip mappend . convert) ep
               & hsSymmetricState .~ ss
  else do
    put $ hs' & hsMsgBuffer .~ input
    iterM (evalMsgToken opRole) $ hoistFT (return . runIdentity) t

    hs'' <- get

    let remaining = hs'' ^. hsMsgBuffer
        dec       = decryptAndHash (cipherBytesToText (convert remaining))
                    $ hs'' ^. hsSymmetricState

    (dp, ss) <- either (const . throwError . HandshakeError $ "handshake payload failed to decrypt") return dec

    put $ hs'' & hsMsgBuffer      .~ convert dp
               & hsSymmetricState .~ ss

  next

evalPattern :: (Cipher c, DH d, Hash h)
            => HandshakePatternF (Handshake c d h ())
            -> Handshake c d h ()
evalPattern (PreInitiator t next) = do
  iterM (evalPreMsgToken InitiatorRole) $ hoistFT (return . runIdentity) t
  next

evalPattern (PreResponder t next) = do
  iterM (evalPreMsgToken ResponderRole) $ hoistFT (return . runIdentity) t
  next

evalPattern (Initiator t next) = processPatternOp InitiatorRole t next
evalPattern (Responder t next) = processPatternOp ResponderRole t next

evalMsgToken :: forall c d h. (Cipher c, DH d, Hash h)
             => HandshakeRole
             -> TokenF (Handshake c d h ())
             -> Handshake c d h ()
evalMsgToken opRole (E next) = do
  hs <- get

  if opRole == hs ^. hsOpts . hoRole then do
    (_, pk) <- getLocalEphemeral hs
    let pk'     = dhPubToBytes pk
        ss      = hs ^. hsSymmetricState
        ss'     = mixHash pk' ss
        ss''    = if ss' ^. ssHasPSK then mixKey pk' ss' else ss'

    put $ hs & hsSymmetricState .~ ss''
             & hsMsgBuffer      %~ (flip mappend . convert) pk'

  else do
    let (b, rest) = splitAt (dhLength (Proxy :: Proxy d)) $ hs ^. hsMsgBuffer
        reBytes   = convert b
        ss        = hs ^. hsSymmetricState
        ss'       = mixHash reBytes ss
        ss''      = if ss ^. ssHasPSK then mixKey reBytes ss' else ss'
        theirKey  = dhBytesToPub reBytes

    theirKey' <- maybe (throwError . HandshakeError $ "invalid remote ephemeral key") return theirKey

    put $ hs & hsOpts . hoRemoteEphemeral .~ Just theirKey'
             & hsSymmetricState           .~ ss''
             & hsMsgBuffer                .~ rest

  next

evalMsgToken opRole (S next) = do
  hs <- get

  if opRole == hs ^. hsOpts. hoRole then do
    pk <- dhPubToBytes . snd <$> getLocalStatic hs
    let ss  = hs ^. hsSymmetricState
        enc = encryptAndHash (convert pk) ss

    (ct, ss') <- either throwError return enc

    put $ hs & hsSymmetricState .~ ss'
             & hsMsgBuffer      %~ (flip mappend . convert) ct
  else
    if isJust (hs ^. hsOpts ^. hoRemoteStatic)
      then throwError . InvalidHandshakeOptions $ "unable to overwrite remote static key"
      else do
        let hasKey    = hs ^. hsSymmetricState . ssHasKey
            len       = dhLength (Proxy :: Proxy d)
            -- The magic 16 here represents the length of the auth tag.
            d         = if hasKey then len + 16 else len
            (b, rest) = splitAt d $ hs ^. hsMsgBuffer
            ct        = cipherBytesToText . convert $ b
            ss        = hs ^. hsSymmetricState
            dec       = decryptAndHash ct ss

        (pt, ss')     <- either (const . throwError . HandshakeError $ "failed to decrypt remote static key") return dec
        theirKey'     <- maybe (throwError . HandshakeError $ "invalid remote static key provided") return $ dhBytesToPub pt

        put $ hs & hsOpts . hoRemoteStatic .~ Just theirKey'
                 & hsSymmetricState        .~ ss'
                 & hsMsgBuffer             .~ rest

  next

evalMsgToken _ (Dhee next) = do
  hs <- get

  ~(sk, _) <- getLocalEphemeral hs
  rpk      <- getRemoteEphemeral hs

  let ss'  = mixKey (dhPerform sk rpk) $ hs ^. hsSymmetricState

  put $ hs & hsSymmetricState .~ ss'

  next

evalMsgToken opRole (Dhes next) = do
  hs <- get

  if opRole == hs ^. hsOpts . hoRole then do
    let ss = hs ^. hsSymmetricState

    rpk <- getRemoteStatic hs

    ~(sk, _) <- getLocalEphemeral hs
    let dh  = dhPerform sk rpk
        ss' = mixKey dh ss

    put $ hs & hsSymmetricState .~ ss'

    next
  else evalMsgToken (invertRole opRole) $ Dhse next

evalMsgToken opRole (Dhse next) = do
  hs <- get

  if opRole == hs ^. hsOpts . hoRole then do
    let ss = hs ^. hsSymmetricState

    ~(sk, _) <- getLocalStatic hs

    rpk <- getRemoteEphemeral hs
    let dh  = dhPerform sk rpk
        ss' = mixKey dh ss

    put $ hs & hsSymmetricState .~ ss'

    next
  else evalMsgToken (invertRole opRole) $ Dhes next

evalMsgToken _ (Dhss next) = do
  hs <- get

  let ss = hs ^. hsSymmetricState

  ~(sk, _) <- getLocalStatic hs
  rpk      <- getRemoteStatic hs
  let dh  = dhPerform sk rpk
      ss' = mixKey dh ss

  put $ hs & hsSymmetricState .~ ss'

  next

evalPreMsgToken :: (Cipher c, DH d, Hash h)
                => HandshakeRole
                -> TokenF (Handshake c d h ())
                -> Handshake c d h ()
evalPreMsgToken opRole (E next) = do
  hs <- get

  let ss = hs ^. hsSymmetricState
  pk <- if opRole == hs ^. hsOpts . hoRole
    then snd <$> getLocalSemiEphemeral hs
    else getRemoteSemiEphemeral hs

  let ss' = mixHash (dhPubToBytes pk) ss

  put $ hs & hsSymmetricState .~ ss'

  next

evalPreMsgToken opRole (S next) = do
  hs <- get

  let ss = hs ^. hsSymmetricState

  pk <- if opRole == hs ^. hsOpts . hoRole
    then snd <$> getLocalStatic hs
    else getRemoteStatic hs

  let ss' = mixHash (dhPubToBytes pk) ss

  put $ hs & hsSymmetricState .~ ss'

  next

evalPreMsgToken _ _ = error "invalid pre-message pattern token"

getLocalStatic :: HandshakeState c d h
               -> Handshake c d h (KeyPair d)
getLocalStatic hs = maybe (throwError (InvalidHandshakeOptions "local static key not set"))
                          return
                          (hs ^. hsOpts ^. hoLocalStatic)

getLocalSemiEphemeral :: HandshakeState c d h
                      -> Handshake c d h (KeyPair d)
getLocalSemiEphemeral hs = maybe (throwError (InvalidHandshakeOptions "local semi-ephemeral key not set"))
                                 return
                                 (hs ^. hsOpts ^. hoLocalSemiEphemeral)

getLocalEphemeral :: HandshakeState c d h
                  -> Handshake c d h (KeyPair d)
getLocalEphemeral hs = maybe (throwError (InvalidHandshakeOptions "local ephemeral key not set"))
                             return
                             (hs ^. hsOpts ^. hoLocalEphemeral)

getRemoteStatic :: HandshakeState c d h
                -> Handshake c d h (PublicKey d)
getRemoteStatic hs = maybe (throwError (InvalidHandshakeOptions "remote static key not set"))
                           return
                           (hs ^. hsOpts ^. hoRemoteStatic)

getRemoteSemiEphemeral :: HandshakeState c d h
                       -> Handshake c d h (PublicKey d)
getRemoteSemiEphemeral hs = maybe (throwError (InvalidHandshakeOptions "remote semi-ephemeral key not set"))
                                  return
                                  (hs ^. hsOpts ^. hoRemoteSemiEphemeral)

getRemoteEphemeral :: HandshakeState c d h
                   -> Handshake c d h (PublicKey d)
getRemoteEphemeral hs = maybe (throwError (InvalidHandshakeOptions "remote ephemeral key not set"))
                              return
                              (hs ^. hsOpts ^. hoRemoteEphemeral)
