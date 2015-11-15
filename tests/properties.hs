module Main where

import Imports

import qualified CipherState
import qualified SymmetricState
import qualified Handshakes

tests :: TestTree
tests = testGroup "cacophony"
  [ CipherState.tests
  , SymmetricState.tests
  , Handshakes.tests
  ]

main :: IO ()
main = defaultMain tests
