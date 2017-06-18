module Options where

import Data.Attoparsec.ByteString.Char8
import qualified Data.ByteString.Base64 as B64
import Data.ByteString.Char8 (pack)
import System.Console.GetOpt

import Crypto.Noise (ScrubbedBytes, HandshakeRole(..), convert)

import Types

data Options = Options
  { optShowHelp          :: Bool
  , optHandshakeName     :: Maybe HandshakeName
  , optHandshakeRole     :: Maybe HandshakeRole
  , optHandshakePrologue :: Maybe ScrubbedBytes
  , optInputFormat       :: InputFormat
  , optLocalHost         :: Maybe String
  , optLocalPort         :: Maybe String
  , optRemoteHost        :: Maybe String
  , optRemotePort        :: Maybe String
  , optPipeCommand       :: Maybe FilePath
  , optLocalEphemeral    :: Maybe ScrubbedBytes
  , optLocalStatic       :: Maybe ScrubbedBytes
  , optRemoteStatic      :: Maybe ScrubbedBytes
  }

defaultOpts :: Options
defaultOpts = Options
  { optShowHelp          = False
  , optHandshakeName     = Nothing
  , optHandshakeRole     = Nothing
  , optHandshakePrologue = Nothing
  , optInputFormat       = FormatPlain
  , optLocalHost         = Nothing
  , optLocalPort         = Nothing
  , optRemoteHost        = Nothing
  , optRemotePort        = Nothing
  , optPipeCommand       = Nothing
  , optLocalEphemeral    = Nothing
  , optLocalStatic       = Nothing
  , optRemoteStatic      = Nothing
  }

readRole :: String
         -> Maybe HandshakeRole
readRole "initiator" = Just InitiatorRole
readRole "responder" = Just ResponderRole
readRole _           = Nothing

readFormat :: String
           -> InputFormat
readFormat "plain"  = FormatPlain
readFormat "hex"    = FormatHex
readFormat "base64" = FormatBase64
readFormat _        = FormatPlain

options :: [OptDescr (Options -> Options)]
options =
  [ Option ['h'] ["help"]
    (NoArg (\o -> o { optShowHelp = True }))
    "show help"
  , Option ['n'] ["name"]
    (ReqArg (\n o -> o { optHandshakeName = either (const Nothing) Just . parseOnly parseHandshakeName . pack $ n }) "HANDSHAKE PATTERN")
    "handshake pattern to use (e.g. Noise_XX_25519_ChaChaPoly1305_SHA256)"
  , Option ['r'] ["role"]
    (ReqArg (\r o -> o { optHandshakeRole = readRole r }) "{initiator,responder}")
    "handshake role"
  , Option [] ["prologue"]
    (ReqArg (\p o -> o { optHandshakePrologue = Just . convert . pack $ p }) "PLAINTEXT")
    "handshake prologue"
  , Option [] ["format"]
    (ReqArg (\f o -> o { optInputFormat = readFormat f }) "{plain,hex,base64}")
    "input format (default: plain)"
  , Option [] ["lhost"]
    (ReqArg (\h o -> o { optLocalHost = Just h }) "HOSTNAME")
    "local host"
  , Option [] ["lport"]
    (ReqArg (\p o -> o { optLocalPort = Just p }) "PORT")
    "local port"
  , Option [] ["rhost"]
    (ReqArg (\h o -> o { optRemoteHost = Just h }) "HOSTNAME")
    "remote host"
  , Option [] ["rport"]
    (ReqArg (\p o -> o { optRemotePort = Just p }) "PORT")
    "remote port"
  , Option [] ["pipe"]
    (ReqArg (\c o -> o { optPipeCommand = Just c }) "COMMAND")
    "command on which to pipe output"
  , Option [] ["local-ephemeral"]
    (ReqArg (\k o -> o { optLocalEphemeral = Just . convert . B64.decodeLenient . pack $ k }) "BASE64 PRIVATE KEY")
    "your private ephemeral key"
  , Option [] ["local-static"]
    (ReqArg (\k o -> o { optLocalStatic = Just . convert . B64.decodeLenient . pack $ k }) "BASE64 PRIVATE KEY")
    "your private static key"
  , Option [] ["remote-static"]
    (ReqArg (\k o -> o { optRemoteStatic = Just . convert . B64.decodeLenient . pack $ k }) "BASE64 PUBLIC KEY")
    "remote party's public static key"
  ]

header :: String
header = "Usage: noise-repl [OPTION]"

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
      [ "The --pipe option is used to pipe raw Noise messages to/from an"
      , "arbitrary command. The (--{l,r}{host,port}) options are used to do"
      , "the same thing over a UDP socket instead."
      , ""
      , "Any local keys not explicitly provided will be generated at startup."
      ]
