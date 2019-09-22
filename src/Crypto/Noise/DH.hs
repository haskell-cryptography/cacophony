{-# LANGUAGE TypeFamilies #-}
-------------------------------------------------
-- |
-- Module      : Crypto.Noise.DH
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.DH
  ( -- * Classes
    DH(..)
    -- * Types
  , KeyPair
  ) where

import Data.ByteArray (ScrubbedBytes)

-- | Typeclass for Diffie-Hellman key agreement.
class DH d where
  -- | Represents a public key.
  data PublicKey d :: *

  -- | Represents a secret key.
  data SecretKey d :: *

  -- | Returns the name of the DH scheme. This is used when generating
  --   the handshake name.
  dhName           :: proxy d -> ScrubbedBytes

  -- | Returns the length of public keys for this DH scheme in bytes.
  dhLength         :: proxy d -> Int

  -- | Generates a 'KeyPair'.
  dhGenKey         :: IO (KeyPair d)

  -- | Performs DH.
  dhPerform        :: SecretKey d -> PublicKey d -> ScrubbedBytes

  -- | Exports a 'PublicKey'.
  dhPubToBytes     :: PublicKey d -> ScrubbedBytes

  -- | Imports a 'PublicKey'.
  dhBytesToPub     :: ScrubbedBytes -> Maybe (PublicKey d)

  -- | Exports a 'SecretKey'.
  dhSecToBytes     :: SecretKey d -> ScrubbedBytes

  -- | Imports a 'SecretKey'.
  dhBytesToPair    :: ScrubbedBytes -> Maybe (KeyPair d)

  -- | Tests 'PublicKey's for equality.
  dhPubEq :: PublicKey d -> PublicKey d -> Bool

-- | Represents a private/public key pair for a given 'DH'.
type KeyPair d = (SecretKey d, PublicKey d)

instance DH d => Eq (PublicKey d) where
  (==) = dhPubEq
