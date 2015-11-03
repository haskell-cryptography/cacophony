{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.AutoUpdate       (mkAutoUpdate, defaultUpdateSettings, updateAction)
import Control.Exception        (SomeException, displayException, handle)
import Data.Aeson               (encode, object, (.=))
import Data.ByteString          (ByteString)
import Data.ByteString.Char8    (unpack)
import Data.ByteString.Lazy.Char8 (append)
import Data.UnixTime            (formatUnixTime, fromEpochTime)
import Pipes.Network.TCP
import System.Log.FastLogger    (toLogStr, pushLogStr, LoggerSet, newFileLoggerSet)
import System.Posix             (epochTime)
import System.Posix.Files       (setFileCreationMask)

import Handshakes

main :: IO ()
main = do
  logHandle <- openLog "debug.log"
  au <- mkAutoUpdate defaultUpdateSettings { updateAction = getDateTime }
  let exLogger = logException logHandle au

  serve HostAny "7000" $ \(s, ip) -> do
    let clientReceiver = fromSocketTimeout 120000000 s 4096
        clientSender   = toSocket s

    handle (exLogger ip) $ processHandshake (clientReceiver, clientSender)
    return ()

openLog :: FilePath -> IO LoggerSet
openLog file = do
  _ <- setFileCreationMask 0o000
  newFileLoggerSet 1 file

logException :: LoggerSet
             -> IO ByteString
             -> SockAddr
             -> SomeException
             -> IO ()
logException ls getCachedDate ip ex = do
  zdt <- getCachedDate
  pushLogStr ls $ toLogStr $ (`append` "\n") . encode $
    object [ "date"      .= unpack zdt
           , "exception" .= displayException ex
           , "ip"        .= show ip
           ]

getDateTime :: IO ByteString
getDateTime = epochTime >>= formatUnixTime "%Y-%m-%d %H:%M:%S %z" . fromEpochTime
