module Main where

import Imports

import qualified Handshake
import qualified CipherState

tests :: TestTree
tests = testGroup "cacophony"
  [ Handshake.tests
  , CipherState.tests
  ]

main :: IO ()
main = defaultMain tests
