----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.HandshakeState
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.HandshakeState
  ( -- * Types
    HandshakeState(..),
    Descriptor,
    -- * Functions
    runDescriptor,
    handshakeState,
    writeHandshakeMsg,
    readHandshakeMsg,
    writeHandshakeMsgFinal,
    readHandshakeMsgFinal,
    writePayload,
    readPayload
  ) where

import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B (append)
import Data.Functor.Identity (Identity, runIdentity)

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

handshakeState :: (Cipher c, Curve d)
               => ScrubbedBytes
               -> Maybe (KeyPair d)
               -> Maybe (KeyPair d)
               -> Maybe (PublicKey d)
               -> Maybe (PublicKey d)
               -> HandshakeState c d
handshakeState hn = HandshakeState (symmetricHandshake hn)

writeHandshakeMsg :: (Cipher c, Curve d)
                      => HandshakeState c d
                      -> Descriptor c d IO ByteString
                      -> Plaintext
                      -> IO (ByteString, HandshakeState c d)
writeHandshakeMsg hs desc payload = do
  (d, hs') <- runDescriptor desc hs
  let shs        = hssSymmetricHandshake hs
      (ep, shs') = encryptAndHash shs payload
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
    (dp, shs') = decryptAndHash shs $ cipherBytesToText $ convert d
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

writePayload :: Cipher c
             => CipherState c
             -> Plaintext
             -> ByteString
writePayload cs pt = undefined

readPayload :: Cipher c
            => CipherState c
            -> ByteString
            -> Plaintext
readPayload cs bs = undefined
