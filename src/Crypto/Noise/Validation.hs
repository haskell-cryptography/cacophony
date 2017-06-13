-----------------------------------------------------
-- |
-- Module      : Crypto.Noise.Validation
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Validation
  ( -- * Types
    InspectionError(..)
  , ErrorPosition
    -- * Functions
  , validateHandshakePattern
  ) where

import Crypto.Noise.Internal.Handshake.Validation
