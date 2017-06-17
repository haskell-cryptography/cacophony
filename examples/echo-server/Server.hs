{-# LANGUAGE RecordWildCards, GADTs #-}
module Server where

import Control.AutoUpdate          (mkAutoUpdate, defaultUpdateSettings, updateAction)
import Control.Exception           (handle)
import Control.Monad               (join)
import Data.Attoparsec.ByteString
import Data.Bits                   (shiftL, shiftR, (.|.), (.&.))
import Data.ByteString             (ByteString, pack, length)
import Data.IORef                  (IORef, newIORef, readIORef, modifyIORef')
import Data.Maybe                  (fromMaybe, isNothing)
import Data.Monoid                 ((<>))
import Network.Simple.TCP
import Prelude hiding              (log, take, length)
import System.Timeout

import Crypto.Noise.DH

import Log
import Handshake
import Keys
import Options
import Types

parseHeader :: Parser HandshakeName
parseHeader = do
  len <- fromIntegral <$> anyWord8
  hdr <- take len
  either mempty
         return
         (parseOnly parseHandshakeName hdr)

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

readMessage :: IORef ByteString
            -> Socket
            -> IO (Maybe ByteString)
readMessage buf sock = do
  tm <- timeout 60000000 $ parseSocket buf sock parseMessage
  return . join $ tm

writeMessage :: Socket
             -> ByteString
             -> IO ()
writeMessage sock msg = send sock . prependLength $ msg

genEphemeralIfNeeded :: DHType d
                     -> (ByteString -> IO ())
                     -> Options
                     -> IO Options
genEphemeralIfNeeded d log opts@Options{..} = do
  case d of
    Curve25519 -> do
      if isNothing optServerEphemeral25519 then do
        k <- dhGenKey
        log $ "generated ephemeral curve25519 key: " <> secretKeyToB64 k
        return opts { optServerEphemeral25519 = Just k }
      else return opts

    Curve448 -> do
      if isNothing optServerEphemeral448 then do
        k <- dhGenKey
        log $ "generated ephemeral curve448 key: " <> secretKeyToB64 k
        return opts { optServerEphemeral448 = Just k }
      else return opts

startServer :: Options
            -> IO ()
startServer opts@Options{..} = do
  logHandle <- maybe openStdOut openLog optLogFile
  au <- mkAutoUpdate defaultUpdateSettings { updateAction = getDateTime }
  let logEx = logException logHandle au
      log = logMsg logHandle au

  serve HostAny optPort $ \(sock, ip) -> handle (logEx ip) $ do
    log ip "connection established"

    leftoverBufRef <- newIORef ""
    th <- timeout 10000000 $ parseSocket leftoverBufRef sock parseHeader
    case th of
      Nothing             -> log ip "timeout waiting for handshake name"
      Just mHandshakeName -> case mHandshakeName of
        Nothing  -> do
          send sock "failed to parse handshake name\n"
          log ip "failed to parse handshake name"
        Just hsn -> case (hsCipher hsn, hsDH hsn, hsHash hsn) of
          (WrapCipherType c, WrapDHType d, WrapHashType h) -> do
            opts' <- genEphemeralIfNeeded d (log ip) opts

            let pat = hsPatternName hsn
                rho = genOpts d opts' pat
                ns  = genNoiseState c h rho (patternToHandshake pat)

            messageLoop (writeMessage sock)
                        (readMessage leftoverBufRef sock)
                        [optPSK]
                        ns

    log ip "connection closed"
