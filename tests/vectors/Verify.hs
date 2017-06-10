module Verify where

import Data.Aeson           (decode)
import Data.ByteString.Lazy (readFile)
import Data.Monoid          ((<>))
import Prelude hiding       (readFile)
import System.Exit          (exitFailure)

import VectorFile

verifyVectorFile :: FilePath
                 -> IO ()
verifyVectorFile f = do
  fd <- readFile f

  let mvf = decode fd :: Maybe VectorFile

  vf <- maybe (putStrLn ("error decoding " <> f) >> exitFailure) return mvf

  putStrLn $ f <> ": All vectors passed."
