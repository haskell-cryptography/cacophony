module Main where

import Imports

import qualified CipherState
import qualified SymmetricHandshakeState
import qualified Handshake

tests :: TestTree
tests = testGroup "cacophony"
  [ CipherState.tests
  , SymmetricHandshakeState.tests
  , Handshake.tests
  ]

main :: IO ()
main = defaultMain tests
