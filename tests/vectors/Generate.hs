{-# LANGUAGE GADTs, RecordWildCards #-}
module Generate where

import Control.Exception    (SomeException)
import Data.Aeson           (encode)
import Data.ByteString.Lazy (writeFile)
import Data.Either          (isLeft)
import Data.Monoid          ((<>))
import Prelude hiding       (writeFile)

import Crypto.Noise
import Crypto.Noise.DH

import Keys
import VectorFile

genMessage :: (Cipher c, DH d, Hash h)
           => Bool             -- ^ True if we are writing a message
           -> [ScrubbedBytes]  -- ^ List of PSKs available for use
           -> ScrubbedBytes    -- ^ The payload to write/read
           -> NoiseState c d h -- ^ The NoiseState to use
           -> ([ScrubbedBytes], NoiseResult c d h)
genMessage write psks payload state = case result of
  NoiseResultNeedPSK s -> if null psks
    then (psks, NoiseResultException . error $ "not enough PSKs provided for handshake pattern")
    else genMessage write (tail psks) (head psks) s
  r -> (psks, r)
  where
    operation = if write then writeMessage else readMessage
    result    = operation payload state

genMessages :: (Cipher c, DH d, Hash h)
            => Bool             -- ^ Set to False for one-way patterns
            -> NoiseState c d h -- ^ Initiator NoiseState
            -> NoiseState c d h -- ^ Responder NoiseState
            -> [ScrubbedBytes]  -- ^ Initiator PSKs
            -> [ScrubbedBytes]  -- ^ Responder PSKs
            -> [ScrubbedBytes]  -- ^ Payloads
            -> ([Either SomeException Message], ScrubbedBytes)
genMessages swap = go []
  where
    go acc s _ _ _ [] = (acc, handshakeHash s)
    go acc sendingState receivingState spsks rpsks (payload : rest) =
      case genMessage True spsks payload sendingState of
        (spsks', NoiseResultMessage ct sendingState') ->
          case genMessage False rpsks ct receivingState of
            (rpsks', NoiseResultMessage pt receivingState') ->
              if swap
                then go (acc <> [Right (Message pt ct)]) receivingState' sendingState' rpsks' spsks' rest
                else go (acc <> [Right (Message pt ct)]) sendingState' receivingState' spsks' rpsks' rest

            (_, NoiseResultException ex) -> (acc <> [Left ex], handshakeHash sendingState)
            _ -> undefined -- the genMessage function should handle this

        (_, NoiseResultException ex) -> (acc <> [Left ex], handshakeHash sendingState)
        _ -> undefined -- the genMessage function should handle this

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
    idho  = defaultHandshakeOpts InitiatorRole viPrologue
    rdho  = defaultHandshakeOpts ResponderRole vrPrologue

    iopts = setLocalEphemeral (dhBytesToPair =<< viEphemeral)
            . setLocalStatic  (dhBytesToPair =<< viStatic)
            . setRemoteStatic (dhBytesToPub  =<< virStatic)
            $ idho

    ropts = setLocalEphemeral (dhBytesToPair =<< vrEphemeral)
            . setLocalStatic  (dhBytesToPair =<< vrStatic)
            . setRemoteStatic (dhBytesToPub  =<< vrrStatic)
            $ rdho

populateVector :: SomeCipherType
               -> SomeDHType
               -> SomeHashType
               -> [ScrubbedBytes]
               -> Vector
               -> Either [Either SomeException Message] Vector
populateVector (WrapCipherType c)
               (WrapDHType d)
               (WrapHashType h)
               payloads
               v@Vector{..} = do
  let (msgs, hsHash) = genMessages swap ins rns viPSKs vrPSKs payloads
  if any isLeft msgs
    then Left msgs
    else pure $ v { vHash     = Just hsHash
                  , vMessages = either undefined id <$> msgs
                  }
  where
    pat        = hsPatternName vProtoName
    swap       = pat /= PatternN && pat /= PatternK && pat /= PatternX &&
                 pat /= PatternNpsk0 && pat /= PatternKpsk0 && pat /= PatternXpsk1
    opts       = genOpts d v
    (ins, rns) = genNoiseStates c h pat opts

genVector :: HandshakeName
          -> [ScrubbedBytes]
          -> Vector
genVector pat payloads = finalVector
  where
    emptyVector = Vector
      { vName       = Nothing
      , vProtoName  = pat
      , vFail       = False
      , viPrologue  = "John Galt"
      , viPSKs      = []
      , viEphemeral = Nothing
      , viStatic    = Nothing
      , virStatic   = Nothing
      , vrPrologue  = "John Galt"
      , vrPSKs      = []
      , vrEphemeral = Nothing
      , vrStatic    = Nothing
      , vrrStatic   = Nothing
      , vHash       = Nothing
      , vMessages   = []
      }

    c = hsCipher pat
    d = hsDH     pat
    h = hsHash   pat

    finalVector = either (error "failed to generate messages!")
                         id
                         (populateVector c d h payloads . setKeys $ emptyVector)

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
