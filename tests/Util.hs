{-# OPTIONS_GHC -fno-warn-orphans #-}
module Util
       ( Test, Tests
       , driver
       , mkArgTest
       , mkTest
       ) where

import           Control.Monad
import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as S

import           System.Environment (getArgs)
import           Test.QuickCheck
import           Text.Printf

--------------------------------------------------------------------------------
-- Orphans

instance Arbitrary ByteString where
  arbitrary = S.pack `liftM` arbitrary

type Test  = (String, IO (Bool,Int))
type Tests = [Test]

driver :: (Int -> Tests) -> IO ()
driver tests = do
  args <- getArgs
  let n = if null args then 100 else read (head args) :: Int
  (results, passed) <- runTests (tests n)
  _ <- printf "Performed %d tests\n" (sum passed)
  unless (and results) (fail "Not all tests passed!")

runTests :: Tests -> IO ([Bool], [Int])
runTests tests = fmap unzip . forM tests $ \(s, a) ->
  printf "%-45s: " s >> a

mkArgTest :: Testable prop => Int -> prop -> IO (Bool, Int)
mkArgTest ntests prop = do
  r <- quickCheckWithResult stdArgs{maxSuccess=ntests,maxSize=ntests} prop
  return $ extractResult r

mkTest :: Testable prop => prop -> IO (Bool, Int)
mkTest prop = do
  r <- quickCheckResult prop
  return $ extractResult r

extractResult :: Result -> (Bool, Int)
extractResult r =
  case r of
    Success {numTests=n} -> (True , n)
    GaveUp  {numTests=n} -> (True , n)
    Failure {numTests=n} -> (False, n)
    _                    -> (False, 0)
