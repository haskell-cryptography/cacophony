{-# LANGUAGE OverloadedStrings, FlexibleInstances,
    GeneralizedNewtypeDeriving, TemplateHaskell,
    RankNTypes, FlexibleContexts, ScopedTypeVariables #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.HandshakeState
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.HandshakeState
  ( -- * Classes
    MonadHandshake(..),
    -- * Types
    MessagePattern,
    MessagePatternIO,
    HandshakePattern(HandshakePattern),
    HandshakeState,
    -- * Functions
    runMessagePatternT,
    getLocalStaticKey,
    getLocalEphemeralKey,
    getRemoteStaticKey,
    getRemoteEphemeralKey,
    handshakeState,
    writeMessage,
    readMessage,
    writeMessageFinal,
    readMessageFinal,
    encryptPayload,
    decryptPayload
  ) where

import Control.Exception   (throw)
import Control.Lens hiding (re)
import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B (append, splitAt)
import Data.Maybe (fromMaybe, isJust)
import Data.Proxy

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Hash
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.SymmetricState
import Crypto.Noise.Types

newtype MessagePatternT c d h m a = MessagePatternT { unMP :: StateT (HandshakeState c d h) m a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadState(HandshakeState c d h))

runMessagePatternT :: Monad m
                   => MessagePatternT c d h m a
                   -> HandshakeState c d h
                   -> m (a, HandshakeState c d h)
runMessagePatternT = runStateT . unMP

-- | Represents a series of operations that can be performed on a Noise
--   message.
type MessagePattern c d h a = MessagePatternT c d h Identity a

-- | Represents a series of operations that will result in a Noise message.
--   This must be done in IO to facilitate the generation of ephemeral
--   keys.
type MessagePatternIO c d h a = MessagePatternT c d h IO a

-- | Represents a series of message patterns, the first for writing and the
--   second for reading.
data HandshakePattern c d h =
  HandshakePattern { _hpName     :: ByteString
                   , _hpPreMsg   :: Maybe (MessagePattern c d h ())
                   , _hpWriteMsg :: [MessagePatternIO c d h ByteString]
                   , _hpReadMsg  :: [ByteString -> MessagePattern c d h ByteString]
                   }

-- | Contains the state of a handshake.
data HandshakeState c d h =
  HandshakeState { _hssSymmetricState     :: SymmetricState c h
                 , _hssHandshakePattern   :: HandshakePattern c d h
                 , _hssLocalStaticKey     :: Maybe (KeyPair d)
                 , _hssLocalEphemeralKey  :: Maybe (KeyPair d)
                 , _hssRemoteStaticKey    :: Maybe (PublicKey d)
                 , _hssRemoteEphemeralKey :: Maybe (PublicKey d)
                 }

$(makeLenses ''HandshakePattern)
$(makeLenses ''HandshakeState)

class Monad m => MonadHandshake m where
  tokenPreLS :: m ()
  tokenPreRS :: m ()
  tokenPreLE :: m ()
  tokenPreRE :: m ()
  tokenRE    :: ByteString -> m ByteString
  tokenRS    :: ByteString -> m ByteString
  tokenWE    :: MonadIO m => m ByteString
  tokenWS    :: m ByteString
  tokenDHEE  :: m ()
  tokenDHES  :: m ()
  tokenDHSE  :: m ()
  tokenDHSS  :: m ()

instance (Monad m, Cipher c, Curve d, Hash h) => MonadHandshake (MessagePatternT c d h m) where
  tokenPreLS = tokenPreLX hssLocalStaticKey

  tokenPreRS = tokenPreRX hssRemoteStaticKey

  tokenPreLE = tokenPreLX hssLocalEphemeralKey

  tokenPreRE = tokenPreRX hssRemoteEphemeralKey

  tokenRE buf = do
    hs <- get

    let (b, rest) = B.splitAt (curveLength (Proxy :: Proxy d)) buf
        reBytes   = convert b
        ss        = hs ^. hssSymmetricState
        ss'       = mixHash reBytes ss
        ss''      = if ss ^. ssHasPSK then mixKey reBytes ss' else ss'

    put $ hs & hssRemoteEphemeralKey .~ Just (curveBytesToPub reBytes)
             & hssSymmetricState     .~ ss''

    return rest

  tokenRS buf = do
    hs <- get
    if isJust (hs ^. hssRemoteStaticKey) then
      throw . HandshakeStateFailure $ "unable to overwrite remote static key"
    else do
      let hasKey    = hs ^. hssSymmetricState . ssHasKey
          (b, rest) = B.splitAt (d hasKey) buf
          ct        = cipherBytesToText . convert $ b
          ss        = hs ^. hssSymmetricState
          (Plaintext pt, ss') = decryptAndHash ct ss

      put $ hs & hssRemoteStaticKey .~ Just (curveBytesToPub pt)
               & hssSymmetricState  .~ ss'

      return rest

    where
      len           = curveLength (Proxy :: Proxy d)
      d hk
        | hk        = len + 16
        | otherwise = len

  tokenWE = do
    ~kp@(_, pk) <- liftIO curveGenKey
    hs <- get
    let pk'  = curvePubToBytes pk
        ss   = hs ^. hssSymmetricState
        ss'  = mixHash pk' ss
        ss'' = if ss' ^. ssHasPSK then mixKey pk' ss' else ss'
    put $ hs & hssLocalEphemeralKey .~ Just kp
             & hssSymmetricState    .~ ss''
    return . convert $ pk'

  tokenWS = do
    hs <- get
    let pk        = curvePubToBytes . snd . getLocalStaticKey $ hs
        ss        = hs ^. hssSymmetricState
        (ct, ss') = encryptAndHash ((Plaintext . convert) pk) ss
    put $ hs & hssSymmetricState .~ ss'
    return . convert $ ct

  tokenDHEE = do
    hs <- get
    let ss       = hs ^. hssSymmetricState
        ~(sk, _) = getLocalEphemeralKey hs
        rpk      = getRemoteEphemeralKey hs
        dh       = curveDH sk rpk
        ss'      = mixKey dh ss
    put $ hs & hssSymmetricState .~ ss'

  tokenDHES = do
    hs <- get
    let ss       = hs ^. hssSymmetricState
        ~(sk, _) = getLocalEphemeralKey hs
        rpk      = getRemoteStaticKey hs
        dh       = curveDH sk rpk
        ss'      = mixKey dh ss
    put $ hs & hssSymmetricState .~ ss'

  tokenDHSE = do
    hs <- get
    let ss       = hs ^. hssSymmetricState
        ~(sk, _) = getLocalStaticKey hs
        rpk      = getRemoteEphemeralKey hs
        dh       = curveDH sk rpk
        ss'      = mixKey dh ss
    put $ hs & hssSymmetricState .~ ss'

  tokenDHSS = do
    hs <- get
    let ss       = hs ^. hssSymmetricState
        ~(sk, _) = getLocalStaticKey hs
        rpk      = getRemoteStaticKey hs
        dh       = curveDH sk rpk
        ss'      = mixKey dh ss
    put $ hs & hssSymmetricState .~ ss'

getLocalStaticKey :: Curve d => HandshakeState c d h -> KeyPair d
getLocalStaticKey hs = fromMaybe (throw (HandshakeStateFailure "local static key not set"))
                                 (hs ^. hssLocalStaticKey)

getLocalEphemeralKey :: Curve d => HandshakeState c d h -> KeyPair d
getLocalEphemeralKey hs = fromMaybe (throw (HandshakeStateFailure "local ephemeral key not set"))
                                    (hs ^. hssLocalEphemeralKey)

-- | Returns the remote party's public static key. This is useful when
--   the static key has been transmitted to you and you want to save it for
--   future use.
getRemoteStaticKey :: Curve d => HandshakeState c d h -> PublicKey d
getRemoteStaticKey hs = fromMaybe (throw (HandshakeStateFailure "remote static key not set"))
                                  (hs ^. hssRemoteStaticKey)

getRemoteEphemeralKey :: Curve d => HandshakeState c d h -> PublicKey d
getRemoteEphemeralKey hs = fromMaybe (throw (HandshakeStateFailure "remote ephemeral key not set"))
                                     (hs ^. hssRemoteEphemeralKey)

tokenPreLX :: (MonadState (HandshakeState c d h) m, Cipher c, Curve d, Hash h)
           => Lens' (HandshakeState c d h) (Maybe (KeyPair d))
           -> m ()
tokenPreLX keyToView = do
  hs <- get
  let ss      = hs ^. hssSymmetricState
      (_, pk) = fromMaybe (throw (HandshakeStateFailure "tokenPreLX: local key not set"))
                          (hs ^. keyToView)
      ss'     = mixHash (curvePubToBytes pk) ss
  put $ hs & hssSymmetricState .~ ss'

tokenPreRX :: (MonadState (HandshakeState c d h) m, Cipher c, Curve d, Hash h)
           => Lens' (HandshakeState c d h) (Maybe (PublicKey d))
           -> m ()
tokenPreRX keyToView = do
  hs <- get
  let ss  = hs ^. hssSymmetricState
      pk  = fromMaybe (throw (HandshakeStateFailure "tokenPreRX: remote key not set"))
                      (hs ^. keyToView)
      ss' = mixHash (curvePubToBytes pk) ss
  put $ hs & hssSymmetricState .~ ss'

-- | Constructs a HandshakeState. The keys you need to provide are
--   dependent on the type of handshake you are using. If you fail to
--   provide a key that your handshake type depends on, or you provide
--   a static key which is supposed to be set during the exchang, you will
--   receive a 'HandshakeStateFailure' exception.
handshakeState :: forall c d h. (Cipher c, Curve d, Hash h)
               => HandshakePattern c d h
               -- ^ The handshake pattern to use
               -> Plaintext
               -- ^ Prologue
               -> Maybe Plaintext
               -- ^ Pre-shared key
               -> Maybe (KeyPair d)
               -- ^ Local static key
               -> Maybe (KeyPair d)
               -- ^ Local ephemeral key
               -> Maybe (PublicKey d)
               -- ^ Remote public static key
               -> Maybe (PublicKey d)
               -- ^ Remote public ephemeral key
               -> HandshakeState c d h
handshakeState hp (Plaintext pro) (Just (Plaintext psk)) ls le rs re =
  maybe hs' hs'' $ hp ^. hpPreMsg
  where
    hsPro x = x & hssSymmetricState %~ mixHash pro
    hsPSK x = x & hssSymmetricState %~ mixPSK psk
    hs      = HandshakeState (symmetricState (mkHPN hp True)) hp ls le rs re
    hs'     = hsPSK . hsPro $ hs
    hs'' mp = snd . runIdentity $ runMessagePatternT mp hs'

handshakeState hp (Plaintext pro) Nothing ls le rs re =
  maybe hs' hs'' $ hp ^. hpPreMsg
  where
    hsPro x = x & hssSymmetricState %~ mixHash pro
    hs      = HandshakeState (symmetricState (mkHPN hp False)) hp ls le rs re
    hs'     = hsPro hs
    hs'' mp = snd . runIdentity $ runMessagePatternT mp hs'

mkHPN :: forall c d h. (Cipher c, Curve d, Hash h)
      => HandshakePattern c d h
      -> Bool
      -> ScrubbedBytes
mkHPN hp psk = if psk then hpn' ppsk else hpn' p
  where
    p        = bsToSB' "Noise_"
    ppsk     = bsToSB' "NoisePSK_"
    a        = curveName  (Proxy :: Proxy d)
    b        = cipherName (Proxy :: Proxy c)
    c        = hashName   (Proxy :: Proxy h)
    u        = bsToSB' "_"
    hpn' pfx = concatSB [pfx, bsToSB' (hp ^. hpName), u, a, u, b, u, c]

-- | Creates a handshake message. The plaintext can be left empty if no
--   plaintext is to be transmitted. All subsequent handshake processing
--   must use the returned state.
writeMessage :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -- ^ The handshake state
             -> Plaintext
             -- ^ Optional message to transmit
             -> IO (ByteString, HandshakeState c d h)
writeMessage hs payload = do
  let (wmp:wmps) = hs ^. hssHandshakePattern . hpWriteMsg

  (d, hs') <- runMessagePatternT wmp hs

  let (ep, ss') = encryptAndHash payload $ hs' ^. hssSymmetricState
      hs''      = hs' & hssSymmetricState .~ ss'
                      & hssHandshakePattern . hpWriteMsg .~ wmps
  return (d `B.append` convert ep, hs'')

-- | Reads a handshake message. All subsequent handshake processing must
--   use the returned state.
readMessage :: (Cipher c, Curve d, Hash h)
            => HandshakeState c d h
            -- ^ The handshake state
            -> ByteString
            -- ^ The handshake message received
            -> (Plaintext, HandshakeState c d h)
readMessage hs buf = (dp, hs'')
  where
    (rmp:rmps) = hs ^. hssHandshakePattern . hpReadMsg
    (d, hs')   = runIdentity $ runMessagePatternT (rmp buf) hs
    (dp, ss')  = decryptAndHash (cipherBytesToText (convert d))
                 $ hs' ^. hssSymmetricState
    hs''       = hs' & hssSymmetricState .~ ss'
                     & hssHandshakePattern . hpReadMsg .~ rmps

-- | The final call of a handshake negotiation. Used to generate a pair of
--   CipherStates, one for each transmission direction.
writeMessageFinal :: (Cipher c, Curve d, Hash h)
                  => HandshakeState c d h
                  -- ^ The handshake state
                  -> Plaintext
                  -- ^ Optional message to transmit
                  -> IO (ByteString, CipherState c, CipherState c)
writeMessageFinal hs payload = do
  (d, hs') <- writeMessage hs payload
  let (cs1, cs2) = split $ hs' ^. hssSymmetricState
  return (d, cs1, cs2)

-- | The final call of a handshake negotiation. Used to generate a pair of
--   CipherStates, one for each transmission direction.
readMessageFinal :: (Cipher c, Curve d, Hash h)
                 => HandshakeState c d h
                 -- ^ The handshake state
                 -> ByteString
                 -- ^ The handshake message received
                 -> (Plaintext, CipherState c, CipherState c)
readMessageFinal hs buf = (pt, cs1, cs2)
  where
    (pt, hs')  = readMessage hs buf
    (cs1, cs2) = split $ hs' ^. hssSymmetricState

-- | Encrypts a payload. The returned 'CipherState' must be used for all
--   subsequent calls.
encryptPayload :: Cipher c
               => Plaintext
               -- ^ The data to encrypt
               -> CipherState c
               -- ^ The CipherState to use for encryption
               -> (ByteString, CipherState c)
encryptPayload pt cs = ((convert . cipherTextToBytes) ct, cs')
  where
    (ct, cs') = encryptAndIncrement ad pt cs
    ad = AssocData . bsToSB' $ ""

-- | Decrypts a payload. The returned 'CipherState' must be used for all
--   subsequent calls.
decryptPayload :: Cipher c
               => ByteString
               -- ^ The data to decrypt
               -> CipherState c
               -- ^ The CipherState to use for decryption
               -> (Plaintext, CipherState c)
decryptPayload ct cs = (pt, cs')
  where
    (pt, cs') = decryptAndIncrement ad ((cipherBytesToText . convert) ct) cs
    ad = AssocData . bsToSB' $ ""
