{-# LANGUAGE OverloadedStrings, GADTs #-}
module Parse where

import Data.Attoparsec.ByteString (Parser, IResult(..), satisfy, anyWord8, take, parseWith)
import Data.Bits                  ((.|.), shiftL)
import Data.ByteString            (ByteString, pack)
import Data.IORef
import Data.Maybe                 (fromMaybe)
import Data.Monoid                ((<>))
import Data.Word                  (Word8)
import Network.Simple.TCP         (Socket, recv)
import Prelude hiding             (take)

import Types

serializeHeader :: Header
                -> ByteString
serializeHeader (psk, hp, ct, dt, ht) =
  pack [pskByte psk, hpByte hp, ctByte ct, dtByte dt, htByte ht]
  where
    pskByte False = 0
    pskByte True  = 1
    hpByte NoiseNN = 0
    hpByte NoiseKN = 1
    hpByte NoiseNK = 2
    hpByte NoiseKK = 3
    hpByte NoiseNX = 4
    hpByte NoiseKX = 5
    hpByte NoiseXN = 6
    hpByte NoiseIN = 7
    hpByte NoiseXK = 8
    hpByte NoiseIK = 9
    hpByte NoiseXX = 10
    hpByte NoiseIX = 11
    ctByte :: SomeCipherType -> Word8
    ctByte (WrapCipherType CTChaChaPoly1305) = 0
    ctByte (WrapCipherType CTAESGCM)         = 1
    dtByte :: SomeDHType -> Word8
    dtByte (WrapDHType DTCurve25519) = 0
    dtByte (WrapDHType DTCurve448)   = 1
    htByte :: SomeHashType -> Word8
    htByte (WrapHashType HTSHA256)  = 0
    htByte (WrapHashType HTSHA512)  = 1
    htByte (WrapHashType HTBLAKE2s) = 2
    htByte (WrapHashType HTBLAKE2b) = 3

pskByteToBool :: Word8 -> Bool
pskByteToBool 0 = False
pskByteToBool 1 = True
pskByteToBool _ = error "invalid PSK setting"

handshakeByteToType :: Word8 -> HandshakeType
handshakeByteToType 0  = NoiseNN
handshakeByteToType 1  = NoiseKN
handshakeByteToType 2  = NoiseNK
handshakeByteToType 3  = NoiseKK
handshakeByteToType 4  = NoiseNX
handshakeByteToType 5  = NoiseKX
handshakeByteToType 6  = NoiseXN
handshakeByteToType 7  = NoiseIN
handshakeByteToType 8  = NoiseXK
handshakeByteToType 9  = NoiseIK
handshakeByteToType 10 = NoiseXX
handshakeByteToType 11 = NoiseIX
handshakeByteToType _  = error "invalid handshake type"

cipherByteToType :: Word8 -> SomeCipherType
cipherByteToType 0 = WrapCipherType CTChaChaPoly1305
cipherByteToType 1 = WrapCipherType CTAESGCM
cipherByteToType _ = error "invalid cipher type"

curveByteToType :: Word8 -> SomeDHType
curveByteToType 0 = WrapDHType DTCurve25519
curveByteToType 1 = WrapDHType DTCurve448
curveByteToType _ = error "invalid curve type"

hashByteToType :: Word8 -> SomeHashType
hashByteToType 0 = WrapHashType HTSHA256
hashByteToType 1 = WrapHashType HTSHA512
hashByteToType 2 = WrapHashType HTBLAKE2s
hashByteToType 3 = WrapHashType HTBLAKE2b
hashByteToType _ = error "invalid hash type"

headerParser :: Parser Header
headerParser = do
  psk <- satisfy (< 2)
  hsb <- satisfy (< 13)
  cib <- satisfy (< 2)
  cub <- satisfy (< 2)
  hb  <- satisfy (< 4)

  return (pskByteToBool psk, handshakeByteToType hsb, cipherByteToType cib, curveByteToType cub, hashByteToType hb)

messageParser :: Parser ByteString
messageParser = do
  l0 <- fromIntegral <$> anyWord8
  l1 <- fromIntegral <$> anyWord8
  take (l0 `shiftL` 8 .|. l1)

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
