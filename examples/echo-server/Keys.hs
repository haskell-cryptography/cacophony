{-# LANGUAGE RecordWildCards #-}
module Keys where

import           Crypto.Random.Entropy  (getEntropy)
import           Data.ByteArray         (convert)
import           Data.ByteString.Char8  (ByteString, unpack)
import qualified Data.ByteString.Base64 as B64
import           Data.Monoid            ((<>))

import Crypto.Noise.DH

data Keys d = Keys
  { serverEphemeral :: KeyPair d
  , serverStatic    :: KeyPair d
  , clientEphemeral :: KeyPair d
  , clientStatic    :: KeyPair d
  }

genKeys :: DH d
        => IO (Keys d)
genKeys = do
  se <- dhGenKey
  ss <- dhGenKey
  ce <- dhGenKey
  cs <- dhGenKey

  return Keys
    { serverEphemeral = se
    , serverStatic    = ss
    , clientEphemeral = ce
    , clientStatic    = cs
    }

keyToArgs :: DH d
          => String
          -> Keys d
          -> ([String], [String])
keyToArgs keyType Keys{..} = (serverArgs, clientArgs)
  where
    privToStr  = unpack . B64.encode . convert . dhSecToBytes . fst
    pubToStr   = unpack . B64.encode . convert . dhPubToBytes . snd
    serverArgs = [ "--server-ephemeral-" <> keyType <> "=" <> privToStr serverEphemeral
                 , "--server-static-"    <> keyType <> "=" <> privToStr serverStatic
                 , "--client-static-"    <> keyType <> "=" <> pubToStr  clientStatic
                 ]
    clientArgs = [ "--client-ephemeral" <> "=" <> privToStr clientEphemeral
                 , "--client-static"    <> "=" <> privToStr clientStatic
                 , "--server-static"    <> "=" <> pubToStr  serverStatic
                 ]

genPSKArg :: IO String
genPSKArg = (unpack . mappend "--psk=" . B64.encode) <$> (getEntropy 32 :: IO ByteString)

secretKeyToB64 :: DH d
               => KeyPair d
               -> ByteString
secretKeyToB64 = B64.encode . convert . dhSecToBytes . fst
