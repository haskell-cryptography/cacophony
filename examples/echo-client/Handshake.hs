{-# LANGUAGE RecordWildCards #-}
module Handshake where

import Data.ByteArray  (ScrubbedBytes, convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as B64

import Crypto.Noise
import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash

import Options
import Types

readPrivateKey :: DH d => ByteString -> Maybe (KeyPair d)
readPrivateKey = dhBytesToPair . convert . B64.decodeLenient

readPublicKey :: DH d => ByteString -> Maybe (PublicKey d)
readPublicKey = dhBytesToPub . convert . B64.decodeLenient

genOpts :: DH d
        => DHType d
        -> Options
        -> PatternName
        -> HandshakeOpts d
genOpts _ Options{..} pat =
  setLocalEphemeral (readPrivateKey =<< optClientEphemeral)
  . setLocalStatic  clientStatic
  . setRemoteStatic serverStatic
  $ dho

  where
    dho = defaultHandshakeOpts InitiatorRole "cacophony"

    clientStatic    = if pat `elem` isPatterns
                        then readPrivateKey =<< optClientStatic
                        else Nothing
    serverStatic    = if pat `elem` irPatterns
                        then readPublicKey =<< optServerStatic
                        else Nothing

    -- The following patterns require a static key for the initiator.
    isPatterns = [ PatternKN
                 , PatternKNpsk0
                 , PatternKNpsk2
                 , PatternKK
                 , PatternKKpsk0
                 , PatternKKpsk2
                 , PatternKX
                 , PatternKXpsk2
                 , PatternXN
                 , PatternXNpsk3
                 , PatternIN
                 , PatternINpsk1
                 , PatternINpsk2
                 , PatternXK
                 , PatternXKpsk3
                 , PatternIK
                 , PatternIKpsk1
                 , PatternIKpsk2
                 , PatternXX
                 , PatternXXpsk3
                 , PatternIX
                 , PatternIXpsk2
                 , PatternK
                 , PatternX
                 , PatternKpsk0
                 , PatternXpsk1
                 ]

    -- The following patterns require the initiator to know the responder's
    -- public static key ahead of time (i.e. it is not transmitted).
    irPatterns = [ PatternNK
                 , PatternNKpsk0
                 , PatternNKpsk2
                 , PatternKK
                 , PatternKKpsk0
                 , PatternKKpsk2
                 , PatternXK
                 , PatternXKpsk3
                 , PatternIK
                 , PatternIKpsk1
                 , PatternIKpsk2
                 , PatternN
                 , PatternK
                 , PatternX
                 , PatternNpsk0
                 , PatternKpsk0
                 , PatternXpsk1
                 ]

genNoiseState :: (Cipher c, DH d, Hash h)
              => CipherType c
              -> HashType h
              -> HandshakeOpts d
              -> HandshakePattern
              -> NoiseState c d h
genNoiseState _ _ = noiseState
