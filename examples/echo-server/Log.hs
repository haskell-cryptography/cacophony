{-# LANGUAGE OverloadedStrings #-}
module Log where

import Control.Exception     (SomeException, displayException)
import Data.Aeson            (encode, object, (.=))
import Data.ByteString       (ByteString)
import Data.ByteString.Char8 (unpack)
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
  (pushLogStr ls . toLogStr) . (<> "\n") . encode $
    object [ "date"    .= unpack zdt
           , "message" .= unpack msg
           , "ip"      .= show ip
           ]

logException :: LoggerSet
             -> IO ByteString
             -> SockAddr
             -> SomeException
             -> IO ()
logException ls getCachedDate ip ex = do
  zdt <- getCachedDate
  (pushLogStr ls . toLogStr) . (<> "\n") . encode $
    object [ "date"      .= unpack zdt
           , "exception" .= displayException ex
           , "ip"        .= show ip
           ]

getDateTime :: IO ByteString
getDateTime = epochTime >>= formatUnixTime "%Y-%m-%d %H:%M:%S %z" . fromEpochTime
