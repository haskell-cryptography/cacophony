{-# LANGUAGE RecordWildCards, GADTs, ScopedTypeVariables #-}
module Main where

import Control.Monad      (when)
import Data.Maybe         (isNothing)
import System.Environment (getArgs)
import System.Exit        (exitFailure)
import System.IO          (hPutStr, stderr)

import Crypto.Noise.DH.Curve25519
import Crypto.Noise.DH.Curve448

import Keys
import Options
import Server

printKeys :: IO ()
printKeys = do
  k25519 <- keyToArgs "25519" <$> (genKeys :: IO (Keys Curve25519))
  k448   <- keyToArgs "448"   <$> (genKeys :: IO (Keys Curve448))
  psk    <- genPSKArg

  putStrLn . unwords $ psk : (fst =<< [k25519, k448])
  putStrLn . unwords $ psk : (snd =<< [k25519, k448])

validateOpts :: Options
             -> IO ()
validateOpts Options{..} = do
  when (optPSK == "") $ do
    putStrLn "Error: A PSK is required (--psk)."
    exitFailure

  when (isNothing optServerStatic25519) $ do
    putStrLn "Error: A static curve25519 key is required (--server-static-25519)."
    exitFailure

  when (isNothing optClientStatic25519) $ do
    putStrLn "Error: A remote static curve25519 key is required (--client-static-25519)."
    exitFailure

  when (isNothing optServerStatic448) $ do
    putStrLn "Error: A static curve448 key is required (--server-static-448)."
    exitFailure

  when (isNothing optClientStatic448) $ do
    putStrLn "Error: A remote curve448 key is required (--client-static-448)."
    exitFailure

processOpts :: Options
             -> IO ()
processOpts o@Options{..}
  | optShowHelp = putStr helpText
  | optGenKeys  = printKeys
  | otherwise   = validateOpts o >> startServer o

main :: IO ()
main = do
  argv <- getArgs
  case parseOptions argv of
    Left errMsg -> hPutStr stderr errMsg
    Right o -> processOpts o
