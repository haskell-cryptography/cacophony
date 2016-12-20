{-# LANGUAGE RecordWildCards, OverloadedStrings #-}
module Main where

import Control.Monad         (forM_)
import Data.ByteArray        (ScrubbedBytes, convert)
import Data.ByteString       (writeFile, readFile)
import qualified Data.ByteString.Base64 as B64 (encode, decodeLenient)
import Data.Maybe            (fromMaybe)
import Data.Monoid           ((<>))
import Prelude hiding        (writeFile, readFile)
import System.Console.GetOpt
import System.Directory      (doesFileExist)
import System.Environment
import System.IO             (stderr, hPutStr, hPutStrLn)

import Crypto.Noise.DH

import Server
import Types

data Options =
  Options { optShowHelp :: Bool
          , optLogFile  :: Maybe FilePath
          }

defaultOptions :: Options
defaultOptions =
  Options { optShowHelp = False
          , optLogFile  = Nothing
          }

options :: [OptDescr (Options -> Options)]
options =
  [ Option ['h'] ["help"]
    (NoArg (\o -> o { optShowHelp = True }))
    "show help"
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
usageHeader = "Usage: echo-server [OPTION] PORT PSK_FILE"

processOptions :: (Options, [String]) -> IO ()
processOptions (Options{..}, [port, pskFile]) = do
  local25519 <- processPrivateKey "server_key_25519"
  local448 <- processPrivateKey "server_key_448"
  remote25519 <- readPublicKey "client_key_25519.pub"
  remote448 <- readPublicKey "client_key_448.pub"
  psk <- readPSK pskFile

  startServer ServerOpts { soLogFile     = optLogFile
                         , soPort        = port
                         , soPSK         = psk
                         , soLocal25519  = local25519
                         , soRemote25519 = remote25519
                         , soLocal448    = local448
                         , soRemote448   = remote448
                         }

processOptions _ = do
  hPutStrLn stderr "error: a port and base64 encoded PSK file must be specified"
  hPutStr stderr $ usageInfo usageHeader options

readPrivateKey :: DH d => FilePath -> IO (KeyPair d)
readPrivateKey f = fromMaybe (error $ "error importing " <> f) . dhBytesToPair . convert <$> readFile f

readPublicKey :: DH d => FilePath -> IO (PublicKey d)
readPublicKey f = (fromMaybe (error $ "error importing " <> f) . dhBytesToPub . convert . B64.decodeLenient) <$> readFile f

readPSK :: FilePath -> IO ScrubbedBytes
readPSK f = convert . B64.decodeLenient <$> readFile f

genAndWriteKey :: DH d => FilePath -> IO (KeyPair d)
genAndWriteKey f = do
  pair@(sec, pub) <- dhGenKey
  writeFile f $ (convert . dhSecToBytes) sec
  writeFile (f <> ".pub") $ (B64.encode . convert . dhPubToBytes) pub
  return pair

processPrivateKey :: DH d => FilePath -> IO (KeyPair d)
processPrivateKey f = do
  exists <- doesFileExist f
  if exists
    then readPrivateKey f
    else genAndWriteKey f

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
