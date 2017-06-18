module Socket where

import Data.ByteString.Char8
import Data.Monoid           ((<>))
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString
import Prelude hiding        (putStrLn)
import System.Exit           (exitFailure)

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
