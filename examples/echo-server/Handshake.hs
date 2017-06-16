{-# LANGUAGE RecordWildCards, GADTs #-}
module Handshake where

import Data.ByteString (ByteString)
import Data.ByteArray  (ScrubbedBytes, convert)

import Crypto.Noise
import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash

import Options
import Types

genOpts :: DH d
        => DHType d
        -> Options
        -> PatternName
        -> HandshakeOpts d
genOpts d Options{..} pat = case d of
  Curve25519 -> setLocalEphemeral (setServerEphemeral optServerEphemeral25519)
                . setLocalStatic  (setServerStatic    optServerStatic25519)
                . setRemoteStatic (setClientStatic    optClientStatic25519)
                $ dho

  Curve448   -> setLocalEphemeral (setServerEphemeral optServerEphemeral448)
                . setLocalStatic  (setServerStatic    optServerStatic448)
                . setRemoteStatic (setClientStatic    optClientStatic448)
                $ dho

  where
    dho = defaultHandshakeOpts ResponderRole "cacophony"

    setServerEphemeral :: DH d => Maybe (KeyPair d) -> Maybe (KeyPair d)
    setServerEphemeral k = if pat `notElem` rePatterns' then k else Nothing

    setServerStatic    :: DH d => Maybe (KeyPair d) -> Maybe (KeyPair d)
    setServerStatic    k = if pat `elem` rsPatterns then k else Nothing

    setClientStatic    :: DH d => Maybe (PublicKey d) -> Maybe (PublicKey d)
    setClientStatic    k = if pat `elem` rrPatterns then k else Nothing

    -- The following patterns do *not* have an ephemeral key for the responder.
    rePatterns' = [ PatternN
                  , PatternK
                  , PatternX
                  , PatternNpsk0
                  , PatternKpsk0
                  , PatternXpsk1
                  ]

    -- The following patterns require a static key for the responder.
    rsPatterns = [ PatternNK
                 , PatternNKpsk0
                 , PatternNKpsk2
                 , PatternKK
                 , PatternKKpsk0
                 , PatternKKpsk2
                 , PatternNX
                 , PatternNXpsk2
                 , PatternKX
                 , PatternKXpsk2
                 , PatternXK
                 , PatternXKpsk3
                 , PatternIK
                 , PatternIKpsk1
                 , PatternIKpsk2
                 , PatternXX
                 , PatternXXpsk3
                 , PatternIX
                 , PatternIXpsk2
                 , PatternN
                 , PatternK
                 , PatternX
                 , PatternNpsk0
                 , PatternKpsk0
                 , PatternXpsk1
                 ]

    -- The following patterns require the responder to know the initiator's
    -- public static key ahead of time (i.e. it is not transmitted).
    rrPatterns = [ PatternKN
                 , PatternKNpsk0
                 , PatternKNpsk2
                 , PatternKK
                 , PatternKKpsk0
                 , PatternKKpsk2
                 , PatternKX
                 , PatternKXpsk2
                 , PatternK
                 , PatternKpsk0
                 ]

genNoiseState :: (Cipher c, DH d, Hash h)
              => CipherType c
              -> HashType h
              -> HandshakeOpts d
              -> HandshakePattern
              -> NoiseState c d h
genNoiseState _ _ = noiseState

messageLoop :: (Cipher c, DH d, Hash h)
            => (ByteString -> IO ())
            -> IO (Maybe ByteString)
            -> [ScrubbedBytes]
            -> NoiseState c d h
            -> IO ()
messageLoop writeCb readCb psks state = do
  mmsg <- (fmap . fmap) convert readCb
  case mmsg of
    Nothing -> return ()
    Just msg -> do
      let (psks', readResult) = processPSKs readMessage psks $ readMessage msg state
      case readResult of
        NoiseResultMessage pt state' -> do
          let (psks'', writeResult) = processPSKs writeMessage psks' $ writeMessage pt state'
          case writeResult of
            NoiseResultMessage ct state'' -> do
              writeCb (convert ct)
              messageLoop writeCb readCb psks'' state''
            NoiseResultException ex -> error $ "error processing message: " `mappend` show ex
        _ -> error "error processing message"
