module Log where

import Control.Exception     (SomeException, displayException)
import Data.ByteString.Char8 (ByteString, pack)
import Data.Monoid           ((<>))
import Data.UnixTime         (formatUnixTime, fromEpochTime)
import Network.Socket        (SockAddr)
import System.Log.FastLogger (toLogStr, pushLogStr, LoggerSet, newFileLoggerSet,
                              newStdoutLoggerSet)
import System.Posix          (epochTime)
import System.Posix.Files    (setFileCreationMask)

openLog :: FilePath -> IO LoggerSet
openLog file = do
  _ <- setFileCreationMask 0o000
  newFileLoggerSet 1024 file

openStdOut :: IO LoggerSet
openStdOut = newStdoutLoggerSet 0

logMsg :: LoggerSet
       -> IO ByteString
       -> SockAddr
       -> ByteString
       -> IO ()
logMsg ls getCachedDate ip msg = do
  zdt <- getCachedDate
  (pushLogStr ls . toLogStr) . (<> "\n") $
    "[" <> zdt <> "] [" <> (pack . show) ip <> "]: " <> msg

logException :: LoggerSet
             -> IO ByteString
             -> SockAddr
             -> SomeException
             -> IO ()
logException ls getCachedDate ip ex = do
  zdt <- getCachedDate
  (pushLogStr ls . toLogStr) . (<> "\n") $
    "[" <> zdt <> "] [" <> (pack . show) ip <> "]: " <> (pack . displayException) ex

getDateTime :: IO ByteString
getDateTime = epochTime >>= formatUnixTime "%Y-%m-%d %H:%M:%S %z" . fromEpochTime
