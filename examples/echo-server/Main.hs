{-# LANGUAGE RecordWildCards, GADTs, ScopedTypeVariables #-}
module Main where

import System.Environment (getArgs)
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

processOpts :: Options
             -> IO ()
processOpts o@Options{..}
  | optShowHelp = putStr helpText
  | optGenKeys  = printKeys
  | otherwise   = startServer o

main :: IO ()
main = do
  argv <- getArgs
  case parseOptions argv of
    Left errMsg -> hPutStr stderr errMsg
    Right o -> processOpts o
