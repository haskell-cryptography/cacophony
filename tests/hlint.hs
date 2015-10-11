module Main where

import Control.Monad
import Language.Haskell.HLint
import System.Environment
import System.Exit

main :: IO ()
main = do
  args <- getArgs
  hints <- hlint $ [ "src"
                   , "benchmarks"
                   , "tests"
                   , "--hint=tests/.hlint"
                   , "--cpp-define=HLINT"
                   ] `mappend` args
  unless (null hints) exitFailure
