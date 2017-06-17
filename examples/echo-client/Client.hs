{-# LANGUAGE RecordWildCards, GADTs #-}
module Client where

import Control.Monad              (join)
import Control.Monad.IO.Class     (liftIO)
import Data.Attoparsec.ByteString
import Data.Bits                  (shiftL, shiftR, (.|.), (.&.))
import Data.ByteArray             (ScrubbedBytes, convert)
import Data.ByteString            (ByteString, pack, length, cons)
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Base64 as B64
import Data.Maybe                 (fromMaybe)
import Data.Monoid                ((<>))
import Data.IORef
import Network.Simple.TCP
import Prelude hiding             (take, length)
import System.Console.Haskeline
import System.Timeout

import Crypto.Noise
import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.DH.Curve25519
import Crypto.Noise.DH.Curve448
import Crypto.Noise.Hash

import Handshake
import Options
import Types

parseMessage :: Parser ByteString
parseMessage = do
  len0 <- fromIntegral <$> anyWord8
  len1 <- fromIntegral <$> anyWord8
  take (len0 `shiftL` 8 .|. len1)

prependLength :: ByteString
              -> ByteString
prependLength msg = pack w16len <> msg
  where
    len    = length msg
    w16len = fmap fromIntegral [(len .&. 0xFF00) `shiftR` 8, len .&. 0xFF]

parseSocket :: IORef ByteString
            -> Socket
            -> Parser a
            -> IO (Maybe a)
parseSocket bufRef sock p = do
  buf <- readIORef bufRef
  result <- parseWith doRead p buf
  case result of
    Fail{}      -> return Nothing
    (Partial _) -> return Nothing
    (Done i r)  -> modifyIORef' bufRef (const i) >> return (Just r)

  where
    doRead = do
      d <- fromMaybe "" <$> recv sock 2048
      modifyIORef' bufRef (<> d)
      return d

readSocket :: IORef ByteString
           -> Socket
           -> IO (Maybe ByteString)
readSocket buf sock = do
  tm <- timeout 60000000 $ parseSocket buf sock parseMessage
  return . join $ tm

writeSocket :: Socket
            -> ByteString
            -> IO ()
writeSocket sock msg = send sock . prependLength $ msg

processInput :: (Cipher c, DH d, Hash h)
             => IORef ByteString
             -> Socket
             -> [ScrubbedBytes]
             -> NoiseState c d h
             -> InputT IO ()
processInput buf sock psks state = do
  minput <- getInputLine "> "
  case minput of
    Nothing -> return ()
    Just "quit" -> return ()
    Just i -> do
      let msg = convert . C8.pack $ i
          (psks', writeResult) = processPSKs writeMessage psks $ writeMessage msg state
      case writeResult of
        NoiseResultMessage ct state' -> do
          liftIO $ writeSocket sock (convert ct)
          response <- liftIO $ readSocket buf sock
          case response of
            Nothing -> liftIO $ putStrLn "connection closed"
            Just r  -> do
              let (psks'', readResult) = processPSKs readMessage psks' $ readMessage (convert r) state'
              case readResult of
                NoiseResultMessage pt state'' -> do
                  liftIO . putStrLn $ "response: " <> show (convert pt :: ByteString)
                  processInput buf sock psks'' state''
                _ -> error "error receiving message"
        _ -> error "error sending message"

secretKeyToB64 :: DH d
               => KeyPair d
               -> ByteString
secretKeyToB64 = B64.encode . convert . dhSecToBytes . fst

genEphemeralIfNeeded :: DHType d
                     -> Options
                     -> IO Options
genEphemeralIfNeeded d opts@Options{..} = do
  case optClientEphemeral of
    Nothing -> do
      k <- case d of
        Curve25519 -> secretKeyToB64 <$> (dhGenKey :: IO (KeyPair Curve25519))
        Curve448   -> secretKeyToB64 <$> (dhGenKey :: IO (KeyPair Curve448))

      putStrLn $ "generated ephemeral key: " <> show k

      return opts { optClientEphemeral = Just k }

    _ -> return opts

startClient :: Options
            -> IO ()
startClient opts@Options{..} = do
  let ehsn = maybe (error "handshake name required")
                   (parseOnly parseHandshakeName)
                   optHandshakeName
      hsn  = either (error "decoding handshake name failed")
                    id
                    ehsn

  case (hsCipher hsn, hsDH hsn, hsHash hsn) of
    (WrapCipherType c, WrapDHType d, WrapHashType h) -> do
      opts' <- genEphemeralIfNeeded d opts

      let pat  = hsPatternName hsn
          iho  = genOpts d opts' pat
          ns   = genNoiseState c h iho (patternToHandshake pat)
          psks = [maybe (error "PSK required") convert optPSK]

      connect optHost optPort $ \(sock, _) -> do
        leftoverBufRef <- newIORef ""
        let hsnStr = C8.pack . show $ hsn
            hdr    = fromIntegral ((length hsnStr) .&. 0xFF) `cons` hsnStr
        send sock hdr
        runInputT defaultSettings (processInput leftoverBufRef sock psks ns)
