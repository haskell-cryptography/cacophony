{-# LANGUAGE RecordWildCards #-}
module Main where

import Control.Monad      (when, unless)
import Data.Bits          (xor)
import Data.Maybe         (isNothing, isJust)
import System.Environment (getArgs)
import System.Exit        (exitFailure)
import System.IO          (hPutStr, stderr)

import Client
import Options

validateOpts :: Options
             -> IO ()
validateOpts Options{..} = do
  when (isNothing optHandshakeName) $ do
    putStrLn "Error: A handshake pattern is required (--name)."
    exitFailure

  when (isNothing optHandshakeRole) $ do
    putStrLn "Error: A handshake role is required (--role=[initiator|responder])."
    exitFailure

  when (isNothing optHandshakePrologue) $ do
    putStrLn "Error: A handshake prologue is required (--prologue, plaintext)."
    exitFailure

  when (isNothing optInputFormat) $ do
    putStrLn "Error: An input format is required (--format=[plain|hex|base64])."
    exitFailure

  let networkMode = all isJust [optLocalHost, optLocalPort, optRemoteHost, optRemotePort]
  unless (networkMode `xor` isJust optPipeCommand) $ do
    putStrLn "Error: A set of sending/receiving hosts/ports OR a pipe command must be set (not both nor neither)."
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
