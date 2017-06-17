{-# LANGUAGE GADTs #-}
module Main where

import Criterion.Main

import Crypto.Noise
import Crypto.Noise.DH

import Keys
import Types

genMessage :: (Cipher c, DH d, Hash h)
           => Bool                -- ^ True if we are writing a message
           -> Maybe ScrubbedBytes -- ^ If a PSK is called for, this value will be used
           -> ScrubbedBytes       -- ^ The payload to write/read
           -> NoiseState c d h    -- ^ The NoiseState to use
           -> NoiseResult c d h
genMessage write mpsk payload state = case result of
  NoiseResultNeedPSK s -> case mpsk of
    Nothing -> NoiseResultException . error $ "PSK requested but none has been configured"
    Just k  -> genMessage write mpsk k s
  r -> r
  where
    operation = if write then writeMessage else readMessage
    result    = operation payload state

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
      case genMessage True mpsk "" sendingState of
        NoiseResultMessage ct sendingState' ->
          case genMessage False mpsk ct receivingState of
            NoiseResultMessage pt receivingState' ->
              if swap
                then go ((pt, ct) : acc) receivingState' sendingState' mpsk
                else go ((pt, ct) : acc) sendingState' receivingState' mpsk
            _ -> error $ "problem encountered during message generation"
        _ -> error $ "problem encountered during message generation"

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
    idho  = defaultHandshakeOpts InitiatorRole mempty
    rdho  = defaultHandshakeOpts ResponderRole mempty

    keys  = getKeys (WrapDHType d) pat

    iopts = setLocalEphemeral (dhBytesToPair =<< hskInitEphemeral    keys)
            . setLocalStatic  (dhBytesToPair =<< hskInitStatic       keys)
            . setRemoteStatic (dhBytesToPub  =<< hskInitRemoteStatic keys)
            $ idho

    ropts = setLocalEphemeral (dhBytesToPair =<< hskRespEphemeral    keys)
            . setLocalStatic  (dhBytesToPair =<< hskRespStatic       keys)
            . setRemoteStatic (dhBytesToPub  =<< hskRespRemoteStatic keys)
            $ rdho

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
