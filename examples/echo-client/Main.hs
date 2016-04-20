{-# LANGUAGE RecordWildCards, OverloadedStrings #-}
module Main where

import Control.Monad         (forM_)
import Data.ByteString       (writeFile, readFile)
import qualified Data.ByteString.Base64 as B64 (encode, decode)
import Data.ByteString.Char8 (pack)
import Data.Maybe            (fromMaybe)
import Data.Monoid           ((<>))
import Prelude hiding        (writeFile, readFile)
import System.Console.GetOpt
import System.Directory      (doesFileExist)
import System.Environment
import System.IO             (stderr, hPutStr, hPutStrLn)

import Crypto.Noise.DH
import Crypto.Noise.DH.Curve25519
import Crypto.Noise.DH.Curve448
import Data.ByteArray.Extend

import Client

data Options =
  Options { optShowHelp :: Bool
          , optPSK      :: Maybe ScrubbedBytes
          , optPrologue :: ScrubbedBytes
          }

defaultOptions :: Options
defaultOptions =
  Options { optShowHelp = False
          , optPSK      = Nothing
          , optPrologue = ""
          }

options :: [OptDescr (Options -> Options)]
options =
  [ Option ['h'] ["help"]
    (NoArg (\o -> o { optShowHelp = True }))
    "show help"
  , Option [] ["psk"]
    (ReqArg (\p o -> o { optPSK = (Just . convert . pack) p }) "STRING")
    "pre-shared key (default: off)"
  , Option [] ["prologue"]
    (ReqArg (\p o -> o { optPrologue = (convert . pack) p }) "STRING")
    "prologue (default: empty string)"
  ]

parseOptions :: [String] -> Either [String] (Options, [String])
parseOptions argv =
  case getOpt Permute options argv of
    (o, n, [])   -> Right (foldl (flip id) defaultOptions o, n)
    (_, _, errs) -> Left errs

usageHeader :: String
usageHeader = "Usage: echo-server [OPTION] HOSTNAME PORT"

processOptions :: (Options, [String]) -> IO ()
processOptions (Options{..}, [hostname, port]) = do
  localKey <- processPrivateKey "client_key_25519" :: IO (KeyPair Curve25519)
  _ <- processPrivateKey "client_key_448" :: IO (KeyPair Curve448)
  remoteKey <- readPublicKey "server_key_25519.pub" :: IO (PublicKey Curve25519)
  runClient hostname port optPrologue optPSK localKey remoteKey

processOptions (_, _) = do
  hPutStrLn stderr "error: a hostname and port must be specified"
  hPutStr stderr $ usageInfo usageHeader options

readPrivateKey :: DH d => FilePath -> IO (KeyPair d)
readPrivateKey f = fromMaybe (error $ "error importing " <> f) . dhBytesToPair . convert <$> readFile f

readPublicKey :: DH d => FilePath -> IO (PublicKey d)
readPublicKey f = (fromMaybe (error $ "error importing " <> f) . dhBytesToPub . convert . either (error ("error decoding " <> f)) id . B64.decode) <$> readFile f

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
