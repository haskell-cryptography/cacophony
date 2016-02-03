module Instances where

import Control.DeepSeq (NFData(..))

import Crypto.Noise.Types (Plaintext(..))

instance NFData Plaintext where
  rnf (Plaintext p) = rnf p
