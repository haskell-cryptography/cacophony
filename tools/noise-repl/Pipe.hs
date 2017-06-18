module Pipe where

import Control.Monad         (when)
import Data.Bits             (shiftL, shiftR, (.|.), (.&.))
import Data.ByteString       (ByteString, length, head, last, hPut,
                              hGetSome, pack)
import qualified Data.ByteString.Char8 as C8
import Data.Monoid           ((<>))
import Prelude hiding        (length, head, last)
import System.Exit           (exitFailure)
import System.IO             (hSetBuffering, BufferMode(..))
import System.Process

genPipe :: FilePath
        -> IO (C8.ByteString -> IO (), IO C8.ByteString)
genPipe cmd = do
  let procSettings = (shell cmd) { std_in  = CreatePipe
                                 , std_out = CreatePipe
                                 }

  (Just stdin, Just stdout, _, _) <- createProcess procSettings

  hSetBuffering stdin NoBuffering
  hSetBuffering stdout NoBuffering

  return (hPut stdin . prependLength, readLength (hGetSome stdout))

prependLength :: ByteString
              -> ByteString
prependLength msg = pack w16len <> msg
  where
    len    = length msg
    w16len = fmap fromIntegral [(len .&. 0xFF00) `shiftR` 8, len .&. 0xFF]

readLength :: (Int -> IO ByteString)
           -> IO ByteString
readLength f = do
  lenBytes <- f 2

  when (length lenBytes < 2) $ do
    putStrLn "error: failed to read pipe"
    exitFailure

  let [len0, len1] = [head lenBytes, last lenBytes]
      len          = fromIntegral $ len0 `shiftL` 8 .|. len1
  f len
