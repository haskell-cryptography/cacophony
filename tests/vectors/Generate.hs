{-# LANGUAGE OverloadedStrings, GADTs #-}
module Generate where

import Control.Concurrent.Async (mapConcurrently)
import Control.Lens             ((^.))
import Data.Aeson               (encode)
import Data.ByteArray           (ScrubbedBytes, convert)
import Data.ByteString          (ByteString)
import Data.ByteString.Lazy     (writeFile)
import Data.Maybe               (fromJust)
import Data.Monoid              ((<>))
import Prelude hiding           (writeFile)

import Crypto.Noise
import Crypto.Noise.Cipher
import Crypto.Noise.DH
import Crypto.Noise.Hash
import Crypto.Noise.Internal.NoiseState

--import Handshakes
import Keys
import VectorFile

genVector :: HandshakeName
          -> Maybe ScrubbedBytes
          -> [ScrubbedBytes]
          -> Vector
genVector pat psk payloads = Vector
  { vName       = pat
  , vFail       = False
  , viPrologue  = "John Galt"
  , viPSK       = psk
  , viEphemeral = Nothing
  , viStatic    = Nothing
  , virStatic   = Nothing
  , vrPrologue  = "John Galt"
  , vrPSK       = psk
  , vrEphemeral = Nothing
  , vrStatic    = Nothing
  , vrrStatic   = Nothing
  , vMessages   = []
  }

allHandshakes :: [HandshakeName]
allHandshakes = do
  pattern <- [minBound .. maxBound]
  cipher  <- [minBound .. maxBound]
  dh      <- [minBound .. maxBound]
  hash    <- [minBound .. maxBound]

  return $ HandshakeName pattern cipher dh hash

genVectorFile :: FilePath
              -> IO ()
genVectorFile f = do
  let payloads = [ "Ludwig von Mises"
                 , "Murray Rothbard"
                 , "F. A. Hayek"
                 , "Carl Menger"
                 , "Jean-Baptiste Say"
                 , "Eugen Böhm von Bawerk"
                 ]
      psk      = "This is my Austrian perspective!"
      vectors  = []

  vs <- mapConcurrently id vectors

  --writeFile f . encode . VectorFile $ vs
  return ()
