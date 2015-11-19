module Instances where

import Control.DeepSeq (NFData(..))

import Crypto.Noise.Cipher

instance NFData Plaintext where
  rnf (Plaintext p) = rnf p
