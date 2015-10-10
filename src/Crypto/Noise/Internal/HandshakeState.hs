{-# LANGUAGE OverloadedStrings, FlexibleInstances #-}
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
    HandshakeState(..),
    Descriptor,
    -- * Functions
    runDescriptor,
    handshakeState,
    writeHandshakeMsg,
    readHandshakeMsg,
    writeHandshakeMsgFinal,
    readHandshakeMsgFinal,
    encryptPayload,
    decryptPayload
  ) where

import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B (append, splitAt)
import Data.Functor.Identity (Identity, runIdentity)
import Data.Maybe (fromJust)

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.SymmetricHandshakeState
import Crypto.Noise.Types

data HandshakeState c d =
  HandshakeState { hssSymmetricHandshake :: SymmetricHandshakeState c
                 , hssLocalStaticKey     :: Maybe (KeyPair d)
                 , hssLocalEphemeralKey  :: Maybe (KeyPair d)
                 , hssRemoteStaticKey    :: Maybe (PublicKey d)
                 , hssRemoteEphemeralKey :: Maybe (PublicKey d)
                 }

type Descriptor c d m a = StateT (HandshakeState c d) m a

runDescriptor :: Monad m => Descriptor c d m a -> HandshakeState c d -> m (a, HandshakeState c d)
runDescriptor = runStateT

class Monad m => MonadHandshake m where
  tokenPreS :: m ()
  tokenPreE :: m ()
  tokenWE   :: MonadIO m => m ByteString
  tokenRE   :: ByteString -> m ByteString
  tokenWS   :: m ByteString
  tokenRS   :: ByteString -> m ByteString
  tokenDHEE :: m ()
  tokenDHES :: m ()
  tokenDHSE :: m ()
  tokenDHSS :: m ()

instance (Monad m, Cipher c, Curve d) => MonadHandshake (StateT (HandshakeState c d) m) where
  tokenPreS = do
    hs <- get
    let shs  = hssSymmetricHandshake hs
        pk   = fromJust . hssRemoteStaticKey $ hs
        shs' = mixHash (curvePubToBytes pk) shs
    put $ hs { hssSymmetricHandshake = shs' }

  tokenPreE = do
    hs <- get
    let shs  = hssSymmetricHandshake hs
        pk   = fromJust . hssRemoteEphemeralKey $ hs
        shs' = mixHash (curvePubToBytes pk) shs
    put $ hs { hssSymmetricHandshake = shs' }

  tokenWE = do
    ~kp@(_, pk) <- liftIO curveGenKey
    hs <- get
    let pk'        = curvePubToBytes pk
        shs        = hssSymmetricHandshake hs
        (ct, shs') = encryptAndHash (Plaintext pk') shs
    put $ hs { hssLocalEphemeralKey = Just kp
             , hssSymmetricHandshake = shs'
             }
    return . convert $ ct

  tokenRE buf = do
    hs <- get
    let hasKey    = shsHasKey . hssSymmetricHandshake $ hs
        (b, rest) = B.splitAt (d hasKey) buf
        ct        = cipherBytesToText . convert $ b
        shs       = hssSymmetricHandshake hs
        (Plaintext pt, shs') = decryptAndHash ct shs
        hs'       = hs { hssRemoteEphemeralKey = Just (curveBytesToPub pt)
                       , hssSymmetricHandshake = shs'
                       }
    put hs'
    return rest
    where
      d hk
        | hk        = 32 + 16
        | otherwise = 32 -- this should call curveLen!

  tokenWS = do
    hs <- get
    let pk         = curvePubToBytes . snd . fromJust . hssLocalStaticKey $ hs
        shs        = hssSymmetricHandshake hs
        (ct, shs') = encryptAndHash ((Plaintext . convert) pk) shs
    put $ hs { hssSymmetricHandshake = shs' }
    return . convert $ ct

  tokenRS buf = do
    hs <- get
    let hasKey    = shsHasKey . hssSymmetricHandshake $ hs
        (b, rest) = B.splitAt (d hasKey) buf
        ct        = cipherBytesToText . convert $ b
        shs       = hssSymmetricHandshake hs
        (Plaintext pt, shs') = decryptAndHash ct shs
        hs'       = hs { hssRemoteStaticKey = Just (curveBytesToPub pt)
                       , hssSymmetricHandshake = shs'
                       }
    put hs'
    return rest
    where
      d hk
        | hk        = 32 + 16
        | otherwise = 32 -- this should call curveLen!

  tokenDHEE = do
    hs <- get
    let shs      = hssSymmetricHandshake hs
        ~(sk, _) = fromJust . hssLocalEphemeralKey $ hs
        rpk      = fromJust . hssRemoteEphemeralKey $ hs
        dh       = curveDH sk rpk
        shs'     = mixKey dh shs
    put $ hs { hssSymmetricHandshake = shs' }

  tokenDHES = do
    hs <- get
    let shs      = hssSymmetricHandshake hs
        ~(sk, _) = fromJust . hssLocalEphemeralKey $ hs
        rpk      = fromJust . hssRemoteStaticKey $ hs
        dh       = curveDH sk rpk
        shs'     = mixKey dh shs
    put $ hs { hssSymmetricHandshake = shs' }

  tokenDHSE = do
    hs <- get
    let shs      = hssSymmetricHandshake hs
        ~(sk, _) = fromJust . hssLocalStaticKey $ hs
        rpk      = fromJust . hssRemoteEphemeralKey $ hs
        dh       = curveDH sk rpk
        shs'     = mixKey dh shs
    put $ hs { hssSymmetricHandshake = shs' }

  tokenDHSS = do
    hs <- get
    let shs      = hssSymmetricHandshake hs
        ~(sk, _) = fromJust . hssLocalStaticKey $ hs
        rpk      = fromJust . hssRemoteStaticKey $ hs
        dh       = curveDH sk rpk
        shs'     = mixKey dh shs
    put $ hs { hssSymmetricHandshake = shs' }


handshakeState :: (Cipher c, Curve d)
               => ScrubbedBytes
               -> Maybe (KeyPair d)
               -> Maybe (KeyPair d)
               -> Maybe (PublicKey d)
               -> Maybe (PublicKey d)
               -> Maybe (Descriptor c d Identity ())
               -> HandshakeState c d
handshakeState hn ls le rs re = maybe hs hs'
  where
    hs = HandshakeState (symmetricHandshake hn) ls le rs re
    hs' desc = snd $ runIdentity $ runDescriptor desc hs

writeHandshakeMsg :: (Cipher c, Curve d)
                      => HandshakeState c d
                      -> Descriptor c d IO ByteString
                      -> Plaintext
                      -> IO (ByteString, HandshakeState c d)
writeHandshakeMsg hs desc payload = do
  (d, hs') <- runDescriptor desc hs
  let shs        = hssSymmetricHandshake hs
      (ep, shs') = encryptAndHash payload shs
      hs''       = hs' { hssSymmetricHandshake = shs' }
  return (d `B.append` convert ep, hs'')

readHandshakeMsg :: (Cipher c, Curve d)
                     => HandshakeState c d
                     -> ByteString
                     -> (ByteString -> Descriptor c d Identity ByteString)
                     -> (Plaintext, HandshakeState c d)
readHandshakeMsg hs buf desc = (dp, hs'')
  where
    (d, hs')   = runIdentity $ runDescriptor (desc buf) hs
    shs        = hssSymmetricHandshake hs
    (dp, shs') = decryptAndHash (cipherBytesToText (convert d)) shs
    hs''       = hs' { hssSymmetricHandshake = shs' }

writeHandshakeMsgFinal :: (Cipher c, Curve d)
                       => HandshakeState c d
                       -> Descriptor c d IO ByteString
                       -> Plaintext
                       -> IO (ByteString, CipherState c, CipherState c)
writeHandshakeMsgFinal hs desc payload = do
  (d, hs') <- writeHandshakeMsg hs desc payload
  let shs        = hssSymmetricHandshake hs'
      (cs1, cs2) = split shs
  return (d, cs1, cs2)

readHandshakeMsgFinal :: (Cipher c, Curve d)
                      => HandshakeState c d
                      -> ByteString
                      -> (ByteString -> Descriptor c d Identity ByteString)
                      -> (Plaintext, CipherState c, CipherState c)
readHandshakeMsgFinal hs buf desc = (pt, cs1, cs2)
  where
    (pt, hs')  = readHandshakeMsg hs buf desc
    shs        = hssSymmetricHandshake hs'
    (cs1, cs2) = split shs

encryptPayload :: Cipher c
             => CipherState c
             -> Plaintext
             -> (ByteString, CipherState c)
encryptPayload cs pt = ((convert . cipherTextToBytes) ct, cs')
  where
    (ct, cs') = encryptAndIncrement ad pt cs
    ad = AssocData $ convert ("" :: ByteString)

decryptPayload :: Cipher c
            => CipherState c
            -> ByteString
            -> (Plaintext, CipherState c)
decryptPayload cs ct = (pt, cs')
  where
    (pt, cs') = decryptAndIncrement ad ((cipherBytesToText . convert) ct) cs
    ad = AssocData $ convert ("" :: ByteString)
