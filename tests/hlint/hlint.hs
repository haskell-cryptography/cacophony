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
                   , "tools"
                   , "--cpp-define=HLINT"
                   , "--ignore=Parse error"
                   , "--ignore=Functor law"
                   ] `mappend` args
  unless (null hints) exitFailure
