module Main where

import Imports

import qualified Handshake

tests :: TestTree
tests = testGroup "cacophony"
  [ Handshake.tests
  ]

main :: IO ()
main = defaultMain tests
