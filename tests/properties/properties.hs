module Main where

import Imports

import qualified CipherState
import qualified SymmetricState
import qualified Handshake

tests :: TestTree
tests = testGroup "cacophony"
  [ CipherState.tests
  , SymmetricState.tests
  , Handshake.tests
  ]

main :: IO ()
main = defaultMain tests
