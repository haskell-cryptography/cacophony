module Options where

import Data.ByteString.Char8 (ByteString, pack)
import System.Console.GetOpt

data Options =
  Options { optShowHelp        :: Bool
          , optHost            :: String
          , optPort            :: String
          , optHandshakeName   :: Maybe ByteString
          , optPSK             :: Maybe ByteString
          , optClientEphemeral :: Maybe ByteString
          , optClientStatic    :: Maybe ByteString
          , optServerStatic    :: Maybe ByteString
          }

defaultOpts :: Options
defaultOpts = Options
  { optShowHelp        = False
  , optHost            = "localhost"
  , optPort            = "4000"
  , optHandshakeName   = Nothing
  , optPSK             = Nothing
  , optClientEphemeral = Nothing
  , optClientStatic    = Nothing
  , optServerStatic    = Nothing
  }

options :: [OptDescr (Options -> Options)]
options =
  [ Option ['h'] ["help"]
    (NoArg (\o -> o { optShowHelp = True }))
    "show help"
  , Option ['c'] ["host"]
    (ReqArg (\h o -> o { optHost = h }) "HOST")
    "host (default: localhost)"
  , Option ['p'] ["port"]
    (ReqArg (\p o -> o { optPort = p }) "PORT")
    "port (default: 4000)"
  , Option ['n'] ["name"]
    (ReqArg (\h o -> o { optHandshakeName = Just . pack $ h }) "HANDSHAKE NAME")
    "handshake name (e.g. Noise_NN_25519_AESGCM_SHA256) [required]"
  , Option [] ["psk"]
    (ReqArg (\k o -> o { optPSK = Just . pack $ k }) "BASE64 PSK")
    "pre-shared key [required]"
  , Option [] ["client-ephemeral"]
    (ReqArg (\k o -> o { optClientEphemeral = Just . pack $ k }) "BASE64 PRIVATE KEY")
    "client's private ephemeral key [optional]"
  , Option [] ["client-static"]
    (ReqArg (\k o -> o { optClientStatic = Just . pack $ k }) "BASE64 PRIVATE KEY")
    "client's private static key [required]"
  , Option [] ["server-static"]
    (ReqArg (\k o -> o { optServerStatic = Just . pack $ k }) "BASE64 PUBLIC KEY")
    "server's public static key [required]"
  ]

header :: String
header = "Usage: echo-client [OPTION]"

parseOptions :: [String]
             -> Either String Options
parseOptions argv =
  case getOpt RequireOrder options argv of
    (o, [], [])   -> Right $ foldl (flip id) defaultOpts o
    (_, _,  errs) -> Left  $ concat errs `mappend` helpText

helpText :: String
helpText = usageInfo header options `mappend` "\n\n" `mappend` extra
  where
    extra = unlines
      [ "The ephemeral key is optional. If it is not specified, a random one will be generated."
      ]
