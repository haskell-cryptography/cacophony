{-# LANGUAGE GADTs #-}
module Keys where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as B16

import Crypto.Noise    (ScrubbedBytes, convert)
import Crypto.Noise.DH
import Crypto.Noise.DH.Curve25519
import Crypto.Noise.DH.Curve448

import Types

data HandshakeKeys = HandshakeKeys
  { hskInitEphemeral    :: Maybe ScrubbedBytes
  , hskRespEphemeral    :: Maybe ScrubbedBytes
  , hskInitStatic       :: Maybe ScrubbedBytes
  , hskRespStatic       :: Maybe ScrubbedBytes
  , hskInitRemoteStatic :: Maybe ScrubbedBytes
  , hskRespRemoteStatic :: Maybe ScrubbedBytes
  }

getKeys :: SomeDHType
        -> PatternName
        -> HandshakeKeys
getKeys dh name = HandshakeKeys
  { hskInitEphemeral    = Just . initiatorEphemeral $ dh
  , hskRespEphemeral    = if name `elem` rePatterns'
                            then Nothing
                            else Just . responderEphemeral $ dh
  , hskInitStatic       = if name `elem` isPatterns
                            then Just . initiatorStatic $ dh
                            else Nothing
  , hskRespStatic       = if name `elem` rsPatterns
                            then Just . responderStatic $ dh
                            else Nothing
  , hskInitRemoteStatic = if name `elem` irPatterns
                            then privateToPublic dh . responderStatic $ dh
                            else Nothing
  , hskRespRemoteStatic = if name `elem` rrPatterns
                            then privateToPublic dh . initiatorStatic $ dh
                            else Nothing
  }

  where
    -- The following patterns do *not* have an ephemeral key for the responder.
    rePatterns' = [ PatternN
                  , PatternK
                  , PatternX
                  , PatternNpsk0
                  , PatternKpsk0
                  , PatternXpsk1
                  ]

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

privateToPublic :: SomeDHType
                -> ScrubbedBytes
                -> Maybe ScrubbedBytes
privateToPublic (WrapDHType Curve25519) k = fmap (dhPubToBytes . snd) (dhBytesToPair k :: Maybe (KeyPair Curve25519))
privateToPublic (WrapDHType Curve448)   k = fmap (dhPubToBytes . snd) (dhBytesToPair k :: Maybe (KeyPair Curve448))

hexToSB :: ByteString
        -> ScrubbedBytes
hexToSB = convert . fst . B16.decode

initiatorEphemeral :: SomeDHType
                   -> ScrubbedBytes
initiatorEphemeral (WrapDHType Curve25519) = hexToSB "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
initiatorEphemeral (WrapDHType Curve448)   = hexToSB "7fd26c8b8a0d5c98c85ff9ca1d7bc66d78578b9f2c4c170850748b27992767e6ea6cc9992a561c9d19dfc342e260c280ef4f3f9b8f879d4e"

responderEphemeral :: SomeDHType
                   -> ScrubbedBytes
responderEphemeral (WrapDHType Curve25519) = hexToSB "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"
responderEphemeral (WrapDHType Curve448)   = hexToSB "3facf7503ebee252465689f1d4e3b1dd219639ef9de4ffd6049d6d71a0f62126840febb99042421ce12af6626d98d9170260390fbc8399a5"

initiatorStatic :: SomeDHType
                -> ScrubbedBytes
initiatorStatic (WrapDHType Curve25519) = hexToSB "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"
initiatorStatic (WrapDHType Curve448)   = hexToSB "34d564c4be963d1b2a89fcfe83e6a72b5e3f5e3127f9f596ffc7575e418dfc1f4e827cfc10c9fed38e92ad56ddf8f08571430df2e76d5411"

responderStatic :: SomeDHType
                -> ScrubbedBytes
responderStatic (WrapDHType Curve25519) = hexToSB "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"
responderStatic (WrapDHType Curve448)   = hexToSB "a9b45971180882a79b89a3399544a425ef8136d278efa443ed67d3ff9d36e883bc330c6295bbf6ed73ff6fd10cbed767ad05ce03ebd27c7c"
