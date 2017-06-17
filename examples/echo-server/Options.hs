module Options where

import           Data.ByteArray         (ScrubbedBytes, convert)
import           Data.ByteString.Char8  (pack)
import qualified Data.ByteString.Base64 as B64
import           System.Console.GetOpt

import Crypto.Noise.DH
import Crypto.Noise.DH.Curve25519
import Crypto.Noise.DH.Curve448

data Options =
  Options { optShowHelp             :: Bool
          , optLogFile              :: Maybe FilePath
          , optPort                 :: String
          , optPSK                  :: ScrubbedBytes
          , optGenKeys              :: Bool
          , optServerEphemeral25519 :: Maybe (KeyPair   Curve25519)
          , optServerStatic25519    :: Maybe (KeyPair   Curve25519)
          , optClientStatic25519    :: Maybe (PublicKey Curve25519)
          , optServerEphemeral448   :: Maybe (KeyPair   Curve448)
          , optServerStatic448      :: Maybe (KeyPair   Curve448)
          , optClientStatic448      :: Maybe (PublicKey Curve448)
          }

defaultOpts :: Options
defaultOpts = Options
  { optShowHelp             = False
  , optLogFile              = Nothing
  , optPort                 = "4000"
  , optPSK                  = ""
  , optGenKeys              = False
  , optServerEphemeral25519 = Nothing
  , optServerStatic25519    = Nothing
  , optClientStatic25519    = Nothing
  , optServerEphemeral448   = Nothing
  , optServerStatic448      = Nothing
  , optClientStatic448      = Nothing
  }

readPrivateKey :: DH d => String -> Maybe (KeyPair d)
readPrivateKey = dhBytesToPair . convert . B64.decodeLenient . pack

readPublicKey :: DH d => String -> Maybe (PublicKey d)
readPublicKey = dhBytesToPub . convert . B64.decodeLenient . pack

options :: [OptDescr (Options -> Options)]
options =
  [ Option ['h'] ["help"]
    (NoArg (\o -> o { optShowHelp = True }))
    "show help"
  , Option ['l'] ["log"]
    (ReqArg (\f o -> o { optLogFile = Just f }) "FILE")
    "log output to file (default: stdout)"
  , Option ['p'] ["port"]
    (ReqArg (\p o -> o { optPort = p }) "PORT")
    "port on which to listen (default: 4000)"
  , Option [] ["psk"]
    (ReqArg (\k o -> o { optPSK = convert . pack $ k }) "BASE64 PSK")
    "pre-shared key [required]"
  , Option ['g'] ["gen-keys"]
    (NoArg (\o -> o { optGenKeys = True }))
    "generate all required keys and format as command line arguments"
  , Option [] ["server-ephemeral-25519"]
    (ReqArg (\k o -> o { optServerEphemeral25519 = readPrivateKey k }) "BASE64 PRIVATE KEY")
    "server's private ephemeral key (Curve25519) [optional]"
  , Option [] ["server-static-25519"]
    (ReqArg (\k o -> o { optServerStatic25519 = readPrivateKey k }) "BASE64 PRIVATE KEY")
    "server's private static key (Curve25519) [required]"
  , Option [] ["client-static-25519"]
    (ReqArg (\k o -> o { optClientStatic25519 = readPublicKey k }) "BASE64 PUBLIC KEY")
    "client's public static key (Curve25519) [required]"
  , Option [] ["server-ephemeral-448"]
    (ReqArg (\k o -> o { optServerEphemeral448 = readPrivateKey k }) "BASE64 PRIVATE KEY")
    "server's private ephemeral key (Curve448) [optional]"
  , Option [] ["server-static-448"]
    (ReqArg (\k o -> o { optServerStatic448 = readPrivateKey k }) "BASE64 PRIVATE KEY")
    "server's private static key (Curve448) [required]"
  , Option [] ["client-static-448"]
    (ReqArg (\k o -> o { optClientStatic448 = readPublicKey k }) "BASE64 PUBLIC KEY")
    "client's public static key (Curve448) [required]"
  ]

header :: String
header = "Usage: echo-server [OPTION]"

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
      [ "Ephemeral keys are optional. If one is not specified, a random one will be generated for each connection."
      , ""
      , "When using --gen-keys, the output is formatted as follows:"
      , "<command line arguments for echo-server>"
      , "<command line arguments for echo-client (curve25519)>"
      , "<command line arguments for echo-client (curve448)>"
      ]
