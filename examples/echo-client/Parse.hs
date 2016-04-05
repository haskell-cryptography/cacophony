{-# LANGUAGE OverloadedStrings #-}
module Parse where

import Data.Attoparsec.ByteString (Parser, IResult(..), anyWord8, take, parseWith)
import Data.Bits                  ((.|.), shiftL)
import Data.ByteString            (ByteString)
import Data.IORef
import Data.Maybe                 (fromMaybe)
import Data.Monoid                ((<>))
import Network.Simple.TCP         (Socket, recv)
import Prelude hiding             (take)

messageParser :: Parser ByteString
messageParser = do
  l0 <- fromIntegral <$> anyWord8
  l1 <- fromIntegral <$> anyWord8
  take (l0 `shiftL` 8 .|. l1)

parseSocket :: IORef ByteString -> Socket -> Parser a -> IO (Maybe a)
parseSocket bufRef sock p = do
  buf <- readIORef bufRef
  result <- parseWith (fromMaybe "" <$> recv sock 2048) p buf
  case result of
    Fail{} -> return Nothing
    (Partial _)  -> return Nothing
    (Done i r)   -> modifyIORef' bufRef (<> i) >> return (Just r)
