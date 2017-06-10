module Verify where

import Control.Exception    (SomeException)
import Control.Monad        (forM_)
import Data.Aeson           (decode)
import Data.Bits
import Data.ByteString.Lazy (readFile)
import Data.Monoid          ((<>))
import qualified Data.Text.IO as TIO
import Prelude hiding       (readFile)
import System.Exit          (exitFailure, exitSuccess)

import VectorFile
import Generate

compareMsgs :: [Message] -- ^ Given messages
            -> [Message] -- ^ Calculated messages
            -> [Maybe (Message, Message)]
compareMsgs given calc = fmap
  (\(m1, m2) -> if m1 == m2
    then Nothing
    else Just (m1, m2)) $ zip given calc

verifyVector :: Vector
             -> Either [Either SomeException Message] [Maybe (Message, Message)]
verifyVector given =
  either Left (Right . compareNoExceptions) rawResults
  where
    c = hsCipher . vName $ given
    d = hsDH     . vName $ given
    h = hsHash   . vName $ given
    rawResults = populateVector c d h (mPayload <$> vMessages given) given
    compareNoExceptions calc = compareMsgs (vMessages given) (vMessages calc)

printMessage :: Message
             -> IO ()
printMessage m = do
  putStrLn "Message:"
  TIO.putStrLn $ "\tPayload:\t" <> (encodeSB . mPayload) m
  TIO.putStrLn $ "\tCiphertext:\t" <> (encodeSB . mCiphertext) m

printMessageComparison :: Message
                       -> Message
                       -> IO ()
printMessageComparison m1 m2 = do
  putStrLn "Message:"
  TIO.putStrLn $ "\tGiven payload:\t\t" <> (encodeSB . mPayload) m1
  TIO.putStrLn $ "\tCalculated ciphertext:\t" <> (encodeSB . mCiphertext) m2
  TIO.putStrLn $ "\tGiven ciphertext:\t" <> (encodeSB . mCiphertext) m1
  TIO.putStrLn $ "\tCalculated payload:\t" <> (encodeSB . mPayload) m2

printExFailure :: [Either SomeException Message]
               -> IO ()
printExFailure = mapM_ $
  either (\ex -> putStrLn $ "Exception: " <> show ex)
         (\m  -> printMessage m)

printComparisonFailure :: [Maybe (Message, Message)]
                       -> IO ()
printComparisonFailure mms =
  if all (== Nothing) mms
    then putStrLn "Given messages and calculated messages are identical."
    else forM_ mms $ maybe (return ()) (uncurry printMessageComparison)

verifyVectorFile :: FilePath
                 -> IO ()
verifyVectorFile f = do
  fd <- readFile f

  let mvf = decode fd :: Maybe VectorFile

  vf <- maybe (putStrLn ("error decoding " <> f) >> exitFailure) return mvf

  let results  = (\(idx, v) -> (idx, v, verifyVector v)) <$> (zip [0..] $ vfVectors vf)
      failures = filter (\(_, v, r) ->
                   (vFail v) `xor` either (const True) (any (/= Nothing)) r)
                   results

  if not (null failures) then do
    putStrLn $ f <> ": The following vectors have failed:\n"
    forM_ failures $ \(idx, vector, result) -> do
      putStrLn "================================================================"
      putStrLn $ "Vector number: " <> show (idx :: Integer)
      putStrLn $ "Handshake name: " <> (show . vName) vector
      putStrLn $ "Should fail?: " <> if vFail vector then "yes" else "no"
      either printExFailure printComparisonFailure result
      putStrLn ""
    exitFailure
  else do
    putStrLn $ f <> ": All vectors passed."
    exitSuccess
