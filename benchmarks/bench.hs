{-# LANGUAGE GADTs #-}
module Main where

import Control.Exception (SomeException)
import Control.Lens
import Criterion.Main
import Data.ByteArray    (ScrubbedBytes)
import Data.Monoid       ((<>))

import Crypto.Noise
import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash hiding (hash)

import Keys
import Types

genMessage :: (Cipher c, DH d, Hash h)
           => Bool                -- ^ True if we are writing a message
           -> Maybe ScrubbedBytes -- ^ If a PSK is called for, this value will be used
           -> ScrubbedBytes       -- ^ The payload to write/read
           -> NoiseState c d h    -- ^ The NoiseState to use
           -> Either SomeException (ScrubbedBytes, NoiseState c d h)
genMessage write mpsk payload state = do
  noiseResult <- operation payload state
  case noiseResult of
    (ResultMessage m, s) -> pure (m, s)
    (ResultNeedPSK, s) -> case mpsk of
      Nothing -> Left . error $ "PSK requested but none has been configured"
      Just k  -> genMessage write mpsk k s

  where
    operation   = if write then writeMessage else readMessage

genMessages :: (Cipher c, DH d, Hash h)
            => Bool                -- ^ Set to False for one-way patterns
            -> NoiseState c d h    -- ^ Initiator NoiseState
            -> NoiseState c d h    -- ^ Responder NoiseState
            -> Maybe ScrubbedBytes -- ^ PSK
            -> [(ScrubbedBytes, ScrubbedBytes)]
genMessages swap = go []
  where
    go acc s r _ | handshakeComplete s && handshakeComplete r = acc
    go acc sendingState receivingState mpsk =
      let result = do
            (ct, sendingState')   <- genMessage True  mpsk "" sendingState
            (pt, receivingState') <- genMessage False mpsk ct receivingState
            pure ((pt, ct), sendingState', receivingState')
      in

      case result of
        Right (msg, sendingState', receivingState') ->
          if swap
            then go (acc <> [msg]) receivingState' sendingState' mpsk
            else go (acc <> [msg]) sendingState' receivingState' mpsk
        Left e -> error $ "exception encountered during message generation: " <> show e

genNoiseStates :: (Cipher c, DH d, Hash h)
               => CipherType c
               -> HashType h
               -> PatternName
               -> (HandshakeOpts d, HandshakeOpts d)
               -> (NoiseState c d h, NoiseState c d h)
genNoiseStates _ _ pat (iopts, ropts) =
  (noiseState iopts hs, noiseState ropts hs)
  where
    hs = patternToHandshake pat

genOpts :: DH d
        => DHType d
        -> PatternName
        -> (HandshakeOpts d, HandshakeOpts d)
genOpts d pat = (iopts, ropts)
  where
    idho  = defaultHandshakeOpts InitiatorRole
    rdho  = defaultHandshakeOpts ResponderRole
    keys  = getKeys (WrapDHType d) pat
    iopts = idho & hoPrologue       .~ ""
                 & hoLocalEphemeral .~ (dhBytesToPair =<< hskInitEphemeral    keys)
                 & hoLocalStatic    .~ (dhBytesToPair =<< hskInitStatic       keys)
                 & hoRemoteStatic   .~ (dhBytesToPub  =<< hskInitRemoteStatic keys)

    ropts = rdho & hoPrologue       .~ ""
                 & hoLocalEphemeral .~ (dhBytesToPair =<< hskRespEphemeral    keys)
                 & hoLocalStatic    .~ (dhBytesToPair =<< hskRespStatic       keys)
                 & hoRemoteStatic   .~ (dhBytesToPub  =<< hskRespRemoteStatic keys)

toBench :: SomeCipherType
        -> SomeDHType
        -> SomeHashType
        -> PatternName
        -> [(ScrubbedBytes, ScrubbedBytes)]
toBench (WrapCipherType c) (WrapDHType d) (WrapHashType h) pat =
  genMessages swap ins rns (Just psk)
  where
    psk        = "This is my Austrian perspective!"
    swap       = pat /= PatternN && pat /= PatternK && pat /= PatternX &&
                 pat /= PatternNpsk0 && pat /= PatternKpsk0 && pat /= PatternXpsk1
    opts       = genOpts d pat
    (ins, rns) = genNoiseStates c h pat opts

allHandshakes :: [HandshakeName]
allHandshakes = do
  pattern <- [minBound .. maxBound]

  cipher  <- [ WrapCipherType AESGCM
             , WrapCipherType ChaChaPoly1305
             ]

  dh      <- [ WrapDHType Curve25519
             , WrapDHType Curve448
             ]

  hash    <- [ WrapHashType BLAKE2b
             , WrapHashType BLAKE2s
             , WrapHashType SHA256
             , WrapHashType SHA512
             ]

  return $ HandshakeName pattern cipher dh hash

main :: IO ()
main = do
  let benches = do
        hs <- allHandshakes
        let b   = toBench (hsCipher hs) (hsDH hs) (hsHash hs)
            pat = hsPatternName hs
        return $ bench (show hs) (nf b pat)

  defaultMain benches
