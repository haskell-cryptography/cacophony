{-# LANGUAGE GADTs, RecordWildCards #-}
module Generate where

import Control.Exception        (SomeException)
import Control.Lens
import Data.Aeson               (encode)
import Data.ByteArray           (ScrubbedBytes)
import Data.ByteString.Lazy     (writeFile)
import Data.Either              (isLeft)
import Data.Monoid              ((<>))
import Prelude hiding           (writeFile)

import Crypto.Noise
import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash hiding (hash)

import Keys
import VectorFile

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
            -> Maybe ScrubbedBytes -- ^ Initiator PSK
            -> Maybe ScrubbedBytes -- ^ Responder PSK
            -> [ScrubbedBytes]     -- ^ Payloads
            -> ([Either SomeException Message], ScrubbedBytes)
genMessages swap = go []
  where
    go acc s _ _ _ [] = (acc, handshakeHash s)
    go acc sendingState receivingState mspsk mrpsk (payload : rest) =
      let result = do
            (ct, sendingState')   <- genMessage True  mspsk payload sendingState
            (pt, receivingState') <- genMessage False mrpsk ct      receivingState
            pure ((Message pt ct), sendingState', receivingState')
      in

      case result of
        Right (msg, sendingState', receivingState') ->
          if swap
            then go (acc <> [Right msg]) receivingState' sendingState' mrpsk mspsk rest
            else go (acc <> [Right msg]) sendingState' receivingState' mspsk mrpsk rest
        Left e -> (acc <> [Left e], handshakeHash sendingState)

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
               -> Either [Either SomeException Message] Vector
populateVector (WrapCipherType c)
               (WrapDHType d)
               (WrapHashType h)
               payloads
               v@Vector{..} = do
  let (msgs, hsHash) = genMessages swap ins rns viPSK vrPSK payloads
  if any isLeft msgs
    then Left msgs
    else pure $ v { vHash     = Just hsHash
                  , vMessages = either undefined id <$> msgs
                  }
  where
    pat        = hsPatternName vName
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
