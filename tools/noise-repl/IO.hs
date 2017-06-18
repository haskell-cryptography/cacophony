module IO where

import Control.Monad         (when)
import Data.Bits             (shiftL, shiftR, (.|.), (.&.))
import qualified Data.ByteString as B
import Data.ByteString.Char8
import Data.Monoid           ((<>))
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString
import Prelude hiding        (putStrLn)
import System.Exit           (exitFailure)
import System.IO             (hSetBuffering, BufferMode(..))
import System.Process

genSocket :: String
          -> String
          -> String
          -> String
          -> IO (ByteString -> IO (), IO ByteString)
genSocket lhost lport rhost rport = do
  let hints   = defaultHints { addrFlags      = [AI_V4MAPPED]
                             , addrSocketType = Datagram
                             , addrFamily     = AF_INET6
                             }

  lais <- getAddrInfo (Just hints) (Just lhost) (Just lport)
  case lais of
    (lai : _) -> do
      sock <- socket AF_INET6 Datagram defaultProtocol
      bind sock (addrAddress lai)
      rais <- getAddrInfo (Just hints) (Just rhost) (Just rport)
      case rais of
        (rai : _) -> do
          let writeSocket d = sendAllTo sock d (addrAddress rai)
              readSocket    = fst <$> recvFrom sock 65535

          return (writeSocket, readSocket)

        _ -> putStrLn ("error resolving hostname: " <> pack rhost) >> exitFailure

    _ -> putStrLn ("error resolving hostname: " <> pack lhost) >> exitFailure

genPipe :: FilePath
        -> IO (ByteString -> IO (), IO ByteString)
genPipe cmd = do
  let procSettings = (shell cmd) { std_in  = CreatePipe
                                 , std_out = CreatePipe
                                 }

  (Just stdin, Just stdout, _, _) <- createProcess procSettings

  hSetBuffering stdin NoBuffering
  hSetBuffering stdout NoBuffering

  return (B.hPut stdin . prependLength, readLength (B.hGetSome stdout))

prependLength :: B.ByteString
              -> B.ByteString
prependLength msg = B.pack w16len <> msg
  where
    len    = B.length msg
    w16len = fmap fromIntegral [(len .&. 0xFF00) `shiftR` 8, len .&. 0xFF]

readLength :: (Int -> IO B.ByteString)
           -> IO B.ByteString
readLength f = do
  lenBytes <- f 2

  when (B.length lenBytes < 2) $ do
    putStrLn "error: failed to read pipe"
    exitFailure

  let [len0, len1] = [B.head lenBytes, B.last lenBytes]
      len          = fromIntegral $ len0 `shiftL` 8 .|. len1
  f len
