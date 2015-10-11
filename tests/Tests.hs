module Main where

import Imports

import qualified Handshake
import qualified CipherState
import qualified SymmetricHandshakeState

tests :: TestTree
tests = testGroup "cacophony"
  [ Handshake.tests
  , CipherState.tests
  , SymmetricHandshakeState.tests
  ]

main :: IO ()
main = defaultMain tests
