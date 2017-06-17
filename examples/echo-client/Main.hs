{-# LANGUAGE RecordWildCards #-}
module Main where

import Control.Monad      (when)
import Data.Maybe         (isNothing)
import System.Environment
import System.Exit        (exitFailure)
import System.IO

import Client
import Options

validateOpts :: Options
             -> IO ()
validateOpts Options{..} = do
  when (isNothing optHandshakeName) $ do
    putStrLn "Error: A handshake name is required (--name)."
    exitFailure

  when (isNothing optPSK) $ do
    putStrLn "Error: A PSK is required (--psk)."
    exitFailure

  when (isNothing optClientStatic) $ do
    putStrLn "Error: A static key is required (--client-static)."
    exitFailure

  when (isNothing optServerStatic) $ do
    putStrLn "Error: A remote static key is required (--client-static)."
    exitFailure

processOpts :: Options
            -> IO ()
processOpts o@Options{..}
  | optShowHelp = putStr helpText
  | otherwise   = validateOpts o >> startClient o

main :: IO ()
main = do
  argv <- getArgs
  case parseOptions argv of
    Left  errMsg -> hPutStr stderr errMsg
    Right o      -> processOpts o
