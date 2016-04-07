module VectorFile where

import Data.Aeson
import Data.ByteString

data Message =
  Message { mPayload    :: ByteString
          , mCiphertext :: ByteString
          , mFail       :: Bool
          }

data Key =
  Key { kName                :: String
      , kType                :: String
      , kStatic              :: Maybe ByteString
      , kSemiephemeral       :: Maybe ByteString
      , kEphemeral           :: Maybe ByteString
      , kRemoteStatic        :: Maybe ByteString
      , kRemoteSemiephemeral :: Maybe ByteString
      }

data Handshake =
  Handshake { hName          :: String
            , hPrologue      :: ByteString
            , hPsk           :: Maybe ByteString
            , hPattern       :: String
            , hCipher        :: String
            , hHash          :: String
            , hInitiatorKeys :: String
            , hResponderKeys :: String
            }

data Vector =
  Vector { vName      :: String
         , vHandshake :: String
         , vMessages  :: [Message]
         }

data VectorFile =
  VectorFile { vfKeys       :: [Key]
             , vfHandshakes :: [Handshake]
             , vfVectors    :: [Vector]
             }
