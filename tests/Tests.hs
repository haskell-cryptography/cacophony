module Main where

import Imports

import qualified HandshakeState

tests :: TestTree
tests = testGroup "cacophony"
  [ HandshakeState.tests
  ]

main :: IO ()
main = defaultMain tests
