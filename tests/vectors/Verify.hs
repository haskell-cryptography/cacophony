{-# LANGUAGE OverloadedStrings, RecordWildCards, ScopedTypeVariables #-}
module Verify where

import Control.Arrow
import Control.Concurrent.Async (mapConcurrently)
import Control.Monad.State
import Data.Aeson               (decode)
import Data.ByteString          (ByteString)
import qualified Data.ByteString.Char8 as BS (putStrLn)
import Data.ByteString.Base16   (encode)
import Data.ByteString.Lazy     (readFile)
import Data.Either
import Data.Maybe               (fromMaybe)
import Data.Monoid              ((<>))
import Prelude hiding           (readFile)
import System.Exit              (exitFailure)

import Crypto.Noise
import Crypto.Noise.Internal.Handshake
import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash
import Data.ByteArray.Extend

import Types
import VectorFile

mkHandshakeOpts :: DH d
                => Vector
                -> DHType d
                -> (HandshakeOpts d, HandshakeOpts d)
mkHandshakeOpts Vector{..} _ = (i, r)
  where
    i = HandshakeOpts { _hoPattern             = hsTypeToPattern vPattern
                      , _hoRole                = InitiatorRole
                      , _hoPrologue            = viPrologue
                      , _hoPreSharedKey        = viPSK
                      , _hoLocalStatic         = viStatic         >>= dhBytesToPair
                      , _hoLocalSemiEphemeral  = viSemiEphemeral  >>= dhBytesToPair
                      , _hoLocalEphemeral      = viEphemeral      >>= dhBytesToPair
                      , _hoRemoteStatic        = virStatic        >>= dhBytesToPub
                      , _hoRemoteSemiEphemeral = virSemiEphemeral >>= dhBytesToPub
                      , _hoRemoteEphemeral     = Nothing
                      }

    r = HandshakeOpts { _hoPattern             = hsTypeToPattern vPattern
                      , _hoRole                = ResponderRole
                      , _hoPrologue            = vrPrologue
                      , _hoPreSharedKey        = vrPSK
                      , _hoLocalStatic         = vrStatic         >>= dhBytesToPair
                      , _hoLocalSemiEphemeral  = vrSemiEphemeral  >>= dhBytesToPair
                      , _hoLocalEphemeral      = vrEphemeral      >>= dhBytesToPair
                      , _hoRemoteStatic        = vrrStatic        >>= dhBytesToPub
                      , _hoRemoteSemiEphemeral = vrrSemiEphemeral >>= dhBytesToPub
                      , _hoRemoteEphemeral     = Nothing
                      }

mkNoiseStates :: (Cipher c, DH d, Hash h)
             => HandshakeOpts d
             -> HandshakeOpts d
             -> CipherType c
             -> HashType h
             -> (NoiseState c d h, NoiseState c d h)
mkNoiseStates iho rho _ _ = (noiseState iho, noiseState rho)

verifyMessage :: (Cipher c, DH d, Hash h)
              => NoiseState c d h
              -> NoiseState c d h
              -> Message
              -> (Either NoiseException (ByteString, ByteString, NoiseState c d h),
                  Either NoiseException (ByteString, ByteString, NoiseState c d h))
verifyMessage sendingState receivingState Message{..} = (sendResult, recvResult)
  where
    payload        = fromMaybe "" mPayload
    writeMsg       = writeMessage sendingState payload
    readMsg        = readMessage receivingState mCiphertext
    convertPayload = either Left (\(p, s) -> Right (convert p, convert payload, s))
    convertCt      = either Left (\(p, s) -> Right (p, mCiphertext , s))
    sendResult     = convertCt writeMsg
    recvResult     = convertPayload readMsg

verifyVector :: Vector
             -> [(Either NoiseException (ByteString, ByteString),
                  Either NoiseException (ByteString, ByteString))]
verifyVector v@Vector{..} =
  case (vCipher, vDH, vHash) of
    (WrapCipherType c, WrapDHType d, WrapHashType h) ->
      let swap       = not $ vPattern == NoiseN || vPattern == NoiseK || vPattern == NoiseX
          (io, ro)   = mkHandshakeOpts v d
          (ins, rns) = mkNoiseStates io ro c h in
      go swap [] ins rns vMessages

  where
    stripState = join (***) (either Left (\(r, e, _) -> Right (r, e)))

    extractState (mr1, mr2) = do
      s1 <- either (const Nothing) (\(_, _, s) -> Just s) mr1
      s2 <- either (const Nothing) (\(_, _, s) -> Just s) mr2
      return (s1, s2)

    go _ acc _ _ [] = acc
    go swap acc sendingState receivingState (msg : rest) =
      let results  = verifyMessage sendingState receivingState msg
          states   = extractState results
          stripped = stripState results in
      maybe (acc <> [stripped]) (\(sendingState', receivingState') ->
        if swap
          then go swap (acc <> [stripped]) receivingState' sendingState' rest
          else go swap (acc <> [stripped]) sendingState' receivingState' rest) states

printFailure :: Int
             -> Bool
             -> Either NoiseException (ByteString, ByteString)
             -> IO ()
printFailure i payload mr =
  case mr of
    Left  e -> putStrLn $ "Message " <> show i <> ": " <> show e
    Right (result, expectation) ->
      when (result /= expectation) $ do
        let component = if payload then " payload:" else " ciphertext:"
        putStrLn $ "Message " <> show i <> component
        BS.putStrLn $ "Calculated value:\t" <> encode result
        BS.putStrLn $ "Expectation:\t\t" <> encode expectation
        putStrLn ""

verifyVectorFile :: FilePath
                 -> IO ()
verifyVectorFile f = do
  fd <- readFile f

  let mvf = decode fd :: Maybe VectorFile

  vf <- maybe (putStrLn ("error decoding " <> f) >> exitFailure) return mvf

  allResults <- mapConcurrently (\v -> return (vName v, verifyVector v, vFail v)) $ vfVectors vf

  let didItFail  = all (== True) . fmap ((== (True, True)) . join (***) (either (const False) (uncurry (==))))
      failures   = filter (\(_, results, mustItFail) -> (didItFail results == mustItFail)) allResults

  if not (null failures) then do
    putStrLn $ f <> ": The following vectors have failed:\n"
    forM_ failures $ \(name, results, mustFail) -> do
      let failStatus = if mustFail then " (must fail)" else ""
      putStrLn $ name <> failStatus <> ": "
      printLoop 0 results

    exitFailure
  else putStrLn $ f <> ": All vectors passed."

  where
    printLoop _ [] = return ()
    printLoop i ((r1, r2) : rest) = do
      printFailure i False r1
      printFailure i True r2
      printLoop (i + 1) rest
