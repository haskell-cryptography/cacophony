{-# LANGUAGE RecordWildCards, OverloadedStrings #-}
module Main where

import Control.Monad         (forM_)
import Data.ByteString       (writeFile, readFile)
import Data.ByteString.Char8 (pack)
import qualified Data.ByteString.Base64 as B64 (encode, decode)
import Data.Monoid           ((<>))
import Prelude hiding        (writeFile, readFile)
import System.Console.GetOpt
import System.Directory      (doesFileExist)
import System.IO             (stderr, hPutStr, hPutStrLn)
import System.Environment

import Crypto.Noise.Curve
import Crypto.Noise.Types
import Data.ByteArray.Extend

import Server
import Types

data Options =
  Options { optListen   :: Maybe String
          , optShowHelp :: Bool
          , optPSK      :: Maybe Plaintext
          , optPrologue :: Plaintext
          , optLogFile  :: Maybe FilePath
          }

defaultOptions :: Options
defaultOptions =
  Options { optListen   = Nothing
          , optShowHelp = False
          , optPSK      = Nothing
          , optPrologue = ""
          , optLogFile  = Nothing
          }

options :: [OptDescr (Options -> Options)]
options =
  [ Option ['p'] []
    (ReqArg (\p o -> o { optListen = Just p}) "PORT")
    "port on which to listen"
  , Option ['h'] ["help"]
    (NoArg (\o -> o { optShowHelp = True }))
    "show help"
  , Option [] ["psk"]
    (ReqArg (\p o -> o { optPSK = (Just . Plaintext . bsToSB' . pack) p }) "STRING")
    "pre-shared key (default: off)"
  , Option [] ["prologue"]
    (ReqArg (\p o -> o { optPrologue = (Plaintext . bsToSB' . pack) p }) "STRING")
    "prologue (default: empty string)"
  , Option ['l'] []
    (ReqArg (\f o -> o { optLogFile = Just f }) "FILE")
    "log output to file (default: stdout)"
  ]

parseOptions :: [String] -> Either [String] (Options, [String])
parseOptions argv =
  case getOpt Permute options argv of
    (o, n, [])   -> Right (foldl (flip id) defaultOptions o, n)
    (_, _, errs) -> Left errs

usageHeader :: String
usageHeader = "Usage: echo-server OPTIONS"

processOptions :: (Options, [String]) -> IO ()
processOptions (Options{..}, _) =
  case optListen of
    Nothing -> do
      hPutStrLn stderr "error: a listen port must be specified"
      hPutStr stderr $ usageInfo usageHeader options
    Just port -> do
      local25519 <- processPrivateKey "local_curve25519"
      remote25519 <- readPublicKey "remote_curve25519.pub"
      local448 <- processPrivateKey "local_curve448"
      remote448 <- readPublicKey "remote_curve448.pub"

      startServer ServerOpts { soLogFile     = optLogFile
                             , soPort        = port
                             , soPrologue    = optPrologue
                             , soPSK         = optPSK
                             , soLocal25519  = local25519
                             , soRemote25519 = remote25519
                             , soLocal448    = local448
                             , soRemote448   = remote448
                             }

readPrivateKey :: Curve d => FilePath -> IO (KeyPair d)
readPrivateKey f = (curveBytesToPair . bsToSB') <$> readFile f

readPublicKey :: Curve d => FilePath -> IO (PublicKey d)
readPublicKey f = (curveBytesToPub . bsToSB' . either (error ("error decoding " <> f)) id . B64.decode) <$> readFile f

genAndWriteKey :: Curve d => FilePath -> IO (KeyPair d)
genAndWriteKey f = do
  pair@(sec, pub) <- curveGenKey
  writeFile f $ (sbToBS' . curveSecToBytes) sec
  writeFile (f <> ".pub") $ (B64.encode . sbToBS' . curvePubToBytes) pub
  return pair

processPrivateKey :: Curve d => FilePath -> IO (KeyPair d)
processPrivateKey f = do
  exists <- doesFileExist f
  if exists then
    readPrivateKey f
  else
    genAndWriteKey f

main :: IO ()
main = do
  argv <- getArgs
  let opts = parseOptions argv
  case opts of
    Left errs -> do
      forM_ errs (hPutStr stderr)
      hPutStr stderr $ usageInfo usageHeader options
    Right o ->
      if optShowHelp . fst $ o
        then putStr $ usageInfo usageHeader options
        else processOptions o
