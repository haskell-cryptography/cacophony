{-# LANGUAGE OverloadedStrings #-}
module Main (
  main
) where

import Util (driver)

main :: IO ()
main = driver $ \_ -> undefined --Foo.tests n
