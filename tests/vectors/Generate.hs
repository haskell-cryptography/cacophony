{-# LANGUAGE OverloadedStrings, GADTs #-}
module Generate where

import Control.Concurrent.Async (mapConcurrently)
import Control.Lens             ((^.))
import Data.Aeson               (encode)
import Data.ByteString          (ByteString)
import qualified Data.ByteString.Base16 as B16
import Data.ByteString.Lazy     (writeFile)
import Data.Maybe               (fromJust)
import Data.Monoid              ((<>))
import Prelude hiding           (writeFile)

import Crypto.Noise
import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash
import Crypto.Noise.Internal.Handshake
import Crypto.Noise.Internal.NoiseState
import Data.ByteArray.Extend

import Handshakes
import Types
import VectorFile

hexToPlaintext :: ByteString
               -> ScrubbedBytes
hexToPlaintext = convert . fst . B16.decode

hexToPair :: DH d
          => ByteString
          -> KeyPair d
hexToPair = fromJust . dhBytesToPair . convert . fst . B16.decode

initiatorEphemeral :: DH d
                   => DHType d
                   -> KeyPair d
initiatorEphemeral DTCurve25519 = hexToPair "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
initiatorEphemeral DTCurve448 = hexToPair "7fd26c8b8a0d5c98c85ff9ca1d7bc66d78578b9f2c4c170850748b27992767e6ea6cc9992a561c9d19dfc342e260c280ef4f3f9b8f879d4e"

responderEphemeral :: DH d
                   => DHType d
                   -> KeyPair d
responderEphemeral DTCurve25519 = hexToPair "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"
responderEphemeral DTCurve448 = hexToPair "3facf7503ebee252465689f1d4e3b1dd219639ef9de4ffd6049d6d71a0f62126840febb99042421ce12af6626d98d9170260390fbc8399a5"

initiatorStatic :: DH d
                => DHType d
                -> KeyPair d
initiatorStatic DTCurve25519 = hexToPair "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"
initiatorStatic DTCurve448 = hexToPair "34d564c4be963d1b2a89fcfe83e6a72b5e3f5e3127f9f596ffc7575e418dfc1f4e827cfc10c9fed38e92ad56ddf8f08571430df2e76d5411"

responderStatic :: DH d
                => DHType d
                -> KeyPair d
responderStatic DTCurve25519 = hexToPair "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"
responderStatic DTCurve448 = hexToPair "a9b45971180882a79b89a3399544a425ef8136d278efa443ed67d3ff9d36e883bc330c6295bbf6ed73ff6fd10cbed767ad05ce03ebd27c7c"

mkKeys :: DH d
       => Plaintext
       -> Maybe ScrubbedBytes
       -> Bool
       -> DHType d
       -> HandshakeKeys d
mkKeys pro psk i d =
  HandshakeKeys { hkPrologue       = pro
                , hkPSK            = psk
                , hkLocalStatic    = if i then initiatorStatic d else responderStatic d
                , hkLocalEphemeral = if i then initiatorEphemeral d else responderEphemeral d
                , hkRemoteStatic   = if i then (snd . responderStatic) d else (snd . initiatorStatic) d
                }

genMessages :: (Cipher c, DH d, Hash h)
            => Bool
            -> NoiseState c d h
            -> NoiseState c d h
            -> [ScrubbedBytes]
            -> [(ScrubbedBytes, ByteString)]
genMessages swap = go []
  where
    go acc _ _ [] = acc
    go acc sendingState receivingState (payload : rest) =
      let writeResult          = writeMessage sendingState payload
          (ct, sendingState')  = either (error "write failed") id writeResult
          (_, receivingState') = either (error "read failed")
                                        id
                                        $ readMessage receivingState ct in
      if swap
        then go (acc <> [(payload, ct)]) receivingState' sendingState' rest
        else go (acc <> [(payload, ct)]) sendingState' receivingState' rest

genVector :: [ScrubbedBytes]
          -> HandshakeType
          -> Maybe ScrubbedBytes
          -> SomeCipherType
          -> SomeDHType
          -> SomeHashType
          -> IO Vector
genVector payloads pat psk cType@(WrapCipherType c) dType@(WrapDHType d) hType@(WrapHashType h) = do
  let ihk  = mkKeys "John Galt" psk True d
      rhk  = mkKeys "John Galt" psk False d
      ins  = mkNoiseState ihk pat InitiatorRole c h
      rns  = mkNoiseState rhk pat ResponderRole c h
      swap = not (pat == NoiseN || pat == NoiseK || pat == NoiseX)
      name = maybe "Noise_" (const "NoisePSK_") psk <>
             show pat                               <>
             "_"                                    <>
             show d                                 <>
             "_"                                    <>
             show c                                 <>
             "_"                                    <>
             show h
      allMsgs = (\(payload, ct) -> Message (Just payload) ct)
                <$> genMessages swap ins rns payloads

  return
    Vector { vName            = name
           , vPattern         = pat
           , vCipher          = cType
           , vDH              = dType
           , vHash            = hType
           , vFail            = False
           , viPrologue       = hkPrologue ihk
           , viPSK            = hkPSK ihk
           , viStatic         = dhSecToBytes . fst <$> ins ^. nsHandshakeState . hsOpts . hoLocalStatic
           , viSemiEphemeral  = Nothing
           , viEphemeral      = dhSecToBytes . fst <$> ins ^. nsHandshakeState . hsOpts . hoLocalEphemeral
           , virStatic        = dhPubToBytes       <$> ins ^. nsHandshakeState . hsOpts . hoRemoteStatic
           , virSemiEphemeral = Nothing
           , vrPrologue       = hkPrologue rhk
           , vrPSK            = hkPSK rhk
           , vrStatic         = dhSecToBytes . fst <$> rns ^. nsHandshakeState . hsOpts . hoLocalStatic
           , vrSemiEphemeral  = Nothing
           , vrEphemeral      = dhSecToBytes . fst <$> rns ^. nsHandshakeState . hsOpts . hoLocalEphemeral
           , vrrStatic        = dhPubToBytes       <$> rns ^. nsHandshakeState . hsOpts . hoRemoteStatic
           , vrrSemiEphemeral = Nothing
           , vMessages        = allMsgs
           }

genVectorFile :: FilePath
              -> IO ()
genVectorFile f = do
  let payloads = ["Ludwig von Mises", "Murray Rothbard", "F. A. Hayek", "Carl Menger", "Jean-Baptiste Say", "Eugen Böhm von Bawerk"]
      patterns = [NoiseNN, NoiseKN, NoiseNK, NoiseKK, NoiseNX, NoiseKX, NoiseXN, NoiseIN, NoiseXK, NoiseIK, NoiseXX, NoiseIX, NoiseN, NoiseK, NoiseX]
      psks     = [Nothing, Just "This is my Austrian perspective!"]
      ciphers  = [WrapCipherType CTChaChaPoly1305, WrapCipherType CTAESGCM]
      dhs      = [WrapDHType DTCurve25519, WrapDHType DTCurve448]
      hashes   = [WrapHashType HTSHA256, WrapHashType HTSHA512, WrapHashType HTBLAKE2s, WrapHashType HTBLAKE2b]
      vectors  = [genVector payloads p psk c d h | p <- patterns, psk <- psks, c <- ciphers, d <- dhs, h <- hashes]

  vs <- mapConcurrently id vectors

  writeFile f . encode . VectorFile $ vs
