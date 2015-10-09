----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.HandshakeState
-- Maintainer  : John Galt <centromere@users.noreply.github.com>
-- Stability   : experimental
-- Portability : POSIX

module Crypto.Noise.Internal.HandshakeState
  ( -- * Types
    HandshakeState,
    -- * Functions
    tokenWE,
    tokenRE,
    tokenDH,
    noiseNNI1,
    noiseNNR1,
    noiseNNR2,
    runDescriptor,
    handshakeState,
    writeHandshakeMessage,
    readHandshakeMessage,
    writePayload,
    readPayload
  ) where

import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B (splitAt, append)
import Data.Functor.Identity (Identity, runIdentity)
import Data.Maybe (fromJust)

import Crypto.Noise.Cipher
import Crypto.Noise.Curve
import Crypto.Noise.Internal.CipherState
import Crypto.Noise.Internal.SymmetricHandshakeState
import Crypto.Noise.Types

type DescriptorT c d m a = StateT (HandshakeState c d) m a

tokenWE :: (Cipher c, Curve d)
        => DescriptorT c d IO ByteString
tokenWE = do
  kp <- liftIO curveGenKey
  hs <- get
  let pk         = snd . curveKeyBytes $ kp
      shs        = hssSymmetricHandshake hs
      (ct, shs') = encryptAndHash shs (Plaintext (convert pk))
  put $ hs { hssLocalEphemeralKey = Just kp
           , hssSymmetricHandshake = shs'
           }
  return . convert $ ct

tokenRE :: (Cipher c, Curve d)
        => ByteString
        -> DescriptorT c d Identity ByteString
tokenRE buf = do
  hs <- get
  let hasKey    = shsHasKey . hssSymmetricHandshake $ hs
      (b, rest) = B.splitAt (d hasKey) buf
      ct        = cipherBytesToText . convert $ b
      shs       = hssSymmetricHandshake hs
      (Plaintext pt, shs') = decryptAndHash shs ct
  put $ hs { hssRemoteEphemeralKey = Just (curveBytesToPub pt)
           , hssSymmetricHandshake = shs'
           }
  return rest
  where
    d hk
      | hk        = 32 + 16
      | otherwise = 32 -- this should call curveLen!

tokenDH :: (Cipher c, Curve d)
        => KeyPair d
        -> PublicKey d
        -> DescriptorT c d Identity ()
tokenDH (sk, _) rpk = do
  hs <- get
  let shs  = hssSymmetricHandshake hs
      dh   = curveDH sk rpk
      shs' = mixKey shs dh
  put $ hs { hssSymmetricHandshake = shs' }

noiseNNI1 :: (Cipher c, Curve d)
          => DescriptorT c d IO ByteString
noiseNNI1 = tokenWE

noiseNNR1 :: (Cipher c, Curve d)
          => ByteString
          -> DescriptorT c d Identity ByteString
noiseNNR1 = tokenRE

noiseNNR2 :: (Cipher c, Curve d)
          => ByteString
          -> DescriptorT c d IO ByteString
noiseNNR2 buf = do
  hs <- get
  e <- tokenWE
  let kp       = fromJust $ hssLocalEphemeralKey hs
      rpk      = fromJust $ hssRemoteEphemeralKey hs
      (_, hs') = runIdentity $ runDescriptor (tokenDH kp rpk) hs
  put hs'
  return e

noiseNNI2 :: (Cipher c, Curve d)
          => ByteString
          -> DescriptorT c d Identity ByteString
noiseNNI2 buf = do
  hs <- get
  rest <- tokenRE buf
  let kp  = fromJust $ hssLocalEphemeralKey hs
      rpk = fromJust $ hssRemoteEphemeralKey hs
  tokenDH kp rpk
  return rest

runDescriptor :: Monad m => DescriptorT c d m a -> HandshakeState c d -> m (a, HandshakeState c d)
runDescriptor = runStateT

data HandshakeState c d =
  HandshakeState { hssSymmetricHandshake :: SymmetricHandshakeState c
                 , hssLocalStaticKey     :: Maybe (KeyPair d)
                 , hssLocalEphemeralKey  :: Maybe (KeyPair d)
                 , hssRemoteStaticKey    :: Maybe (PublicKey d)
                 , hssRemoteEphemeralKey :: Maybe (PublicKey d)
                 }

handshakeState :: (Cipher c, Curve d)
               => ScrubbedBytes
               -> Maybe (KeyPair d)
               -> Maybe (KeyPair d)
               -> Maybe (PublicKey d)
               -> Maybe (PublicKey d)
               -> HandshakeState c d
handshakeState hn = HandshakeState (symmetricHandshake hn)

writeHandshakeMessage :: (Cipher c, Curve d)
                      => HandshakeState c d
                      -> DescriptorT c d IO ByteString
                      -> Bool
                      -> Plaintext
                      -> IO (Either (ByteString, HandshakeState c d)
                                    (CipherState c, CipherState c))
writeHandshakeMessage hs desc final payload
  | final = undefined
  | otherwise = do
    (d, hs') <- runDescriptor desc hs
    let shs        = hssSymmetricHandshake hs
        (ep, shs') = encryptAndHash shs payload
        hs''       = hs' { hssSymmetricHandshake = shs' }
    return $ Left (d `B.append` convert ep, hs'')

readHandshakeMessage :: (Cipher c, Curve d)
                     => HandshakeState c d
                     -> ByteString
                     -> (ByteString -> DescriptorT c d Identity ByteString)
                     -> Bool
                     -> Either (Plaintext, HandshakeState c d)
                               (Plaintext, CipherState c, CipherState c)
readHandshakeMessage hs buf desc final
  | final = undefined
  | otherwise = do
    let (d, hs')   = runIdentity $ runDescriptor (desc buf) hs
        shs        = hssSymmetricHandshake hs
        (dp, shs') = decryptAndHash shs $ cipherBytesToText $ convert d
        hs''       = hs' { hssSymmetricHandshake = shs' }
    Left (dp, hs'')

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
