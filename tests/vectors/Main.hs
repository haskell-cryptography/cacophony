module Main where

import System.Directory (createDirectoryIfMissing, getDirectoryContents)
import System.Exit      (exitSuccess)

import Generate
import Verify

main :: IO ()
main = do
  createDirectoryIfMissing False "vectors"

  vectorFiles <- filter (\f -> (f /= ".") && (f /= "..")) <$> getDirectoryContents "vectors"
  if "cacophony.txt" `notElem` vectorFiles
    then do
      genVectorFile "vectors/cacophony.txt"
      putStrLn "Generated default vectors."
    else mapM_ verifyVectorFile (fmap ("vectors/" <>) vectorFiles) >> exitSuccess
