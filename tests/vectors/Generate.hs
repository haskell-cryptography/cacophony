{-# LANGUAGE OverloadedStrings, GADTs, RecordWildCards #-}
module Generate where

import Control.Lens
import Data.Aeson               (encode)
import Data.ByteArray           (ScrubbedBytes)
import Data.ByteString.Lazy     (writeFile)
import Data.Monoid              ((<>))
import Prelude hiding           (writeFile)

import Crypto.Noise
import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash hiding (hash)

import Keys
import VectorFile

genMessage :: (Cipher c, DH d, Hash h)
           => Bool
           -> Maybe ScrubbedBytes
           -> ScrubbedBytes
           -> NoiseState c d h
           -> (ScrubbedBytes, NoiseState c d h)
genMessage write mpsk payload state =
  (msg, newState)
  where
    operation   = if write then writeMessage else readMessage
    errResult   = operation payload state
    noiseResult = either (\e -> error $ "message generation failed: " <> show e)
                         id
                         errResult
    (msg, newState) = case noiseResult of
      (ResultMessage m, s) -> (m, s)
      (ResultNeedPSK, s) -> case mpsk of
        Nothing -> error "PSK requested but none has been configured"
        Just k  -> genMessage write mpsk k s

genMessages :: (Cipher c, DH d, Hash h)
            => Bool
            -> NoiseState c d h
            -> NoiseState c d h
            -> Maybe ScrubbedBytes
            -> Maybe ScrubbedBytes
            -> [ScrubbedBytes]
            -> [Message]
genMessages swap = go []
  where
    go acc _ _ _ _ [] = acc
    go acc sendingState receivingState mspsk mrpsk (payload : rest) =
      let (ct, newSendingState)   = genMessage True  mspsk payload sendingState
          (pt, newReceivingState) = genMessage False mrpsk ct receivingState in

      if swap
        then go (acc <> [Message pt ct]) newReceivingState newSendingState mrpsk mspsk rest
        else go (acc <> [Message pt ct]) newSendingState newReceivingState mspsk mrpsk rest

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
        -> Vector
        -> (HandshakeOpts d, HandshakeOpts d)
genOpts _ Vector{..} = (iopts, ropts)
  where
    idho  = defaultHandshakeOpts InitiatorRole
    rdho  = defaultHandshakeOpts ResponderRole
    iopts = idho & hoPrologue       .~ viPrologue
                 & hoLocalEphemeral .~ (dhBytesToPair =<< viEphemeral)
                 & hoLocalStatic    .~ (dhBytesToPair =<< viStatic)
                 & hoRemoteStatic   .~ (dhBytesToPub  =<< virStatic)

    ropts = rdho & hoPrologue       .~ vrPrologue
                 & hoLocalEphemeral .~ (dhBytesToPair =<< vrEphemeral)
                 & hoLocalStatic    .~ (dhBytesToPair =<< vrStatic)
                 & hoRemoteStatic   .~ (dhBytesToPub  =<< vrrStatic)

populateVector :: SomeCipherType
               -> SomeDHType
               -> SomeHashType
               -> [ScrubbedBytes]
               -> Vector
               -> Vector
populateVector (WrapCipherType c)
               (WrapDHType d)
               (WrapHashType h)
               payloads
               v@Vector{..} =
  v { vMessages = genMessages swap ins rns viPSK vrPSK payloads }
  where
    pat        = hsPatternName vName
    swap       = pat /= PatternN && pat /= PatternK && pat /= PatternX
    opts       = genOpts d v
    (ins, rns) = genNoiseStates c h pat opts

genVector :: HandshakeName
          -> [ScrubbedBytes]
          -> Vector
genVector pat payloads = finalVector
  where
    emptyVector = Vector
      { vName       = pat
      , vFail       = False
      , viPrologue  = "John Galt"
      , viPSK       = Nothing
      , viEphemeral = Nothing
      , viStatic    = Nothing
      , virStatic   = Nothing
      , vrPrologue  = "John Galt"
      , vrPSK       = Nothing
      , vrEphemeral = Nothing
      , vrStatic    = Nothing
      , vrrStatic   = Nothing
      , vMessages   = []
      }

    c = hsCipher pat
    d = hsDH     pat
    h = hsHash   pat

    finalVector = populateVector c d h payloads . setKeys $ emptyVector

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

genVectorFile :: FilePath
              -> IO ()
genVectorFile f = do
  let payloads = [ "Ludwig von Mises"
                 , "Murray Rothbard"
                 , "F. A. Hayek"
                 , "Carl Menger"
                 , "Jean-Baptiste Say"
                 , "Eugen Böhm von Bawerk"
                 ]
      vectors  = [ genVector hs payloads | hs <- allHandshakes ]

  writeFile f . encode . VectorFile $ vectors
