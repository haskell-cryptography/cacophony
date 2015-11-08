{-# LANGUAGE OverloadedStrings #-}
module HandshakeStates where

import Data.ByteString (ByteString)
import Data.Proxy

import Crypto.Noise.MessagePatterns
import Crypto.Noise.Handshake
import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Hash
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Types

initStatic :: KeyPair Curve25519
initStatic = curveBytesToPair . bsToSB' $ "I\f\232\218A\210\230\147\FS\222\167\v}l\243!\168.\ESC\t\SYN\"\169\179A`\DC28\211\169tC"

respStatic :: KeyPair Curve25519
respStatic = curveBytesToPair . bsToSB' $ "\ETB\157\&7\DC2\252\NUL\148\172\148\133\218\207\&8\221y\144\209\168FX\224Ser_\178|\153.\FSg&"

respEphemeral :: KeyPair Curve25519
respEphemeral = curveBytesToPair . bsToSB' $ "<\231\151\151\180\217\146\DLEI}\160N\163iKc\162\210Y\168R\213\206&gm\169r\SUB[\\'"

makeHSN :: ByteString -> ScrubbedBytes
makeHSN hs = concatSB [p, convert hs, u, a, u, b, u, c]
  where
    a = curveName  (Proxy :: Proxy Curve25519)
    b = cipherName (Proxy :: Proxy ChaChaPoly1305)
    c = hashName   (Proxy :: Proxy SHA256)
    u = bsToSB' "_"
    p = bsToSB' "Noise_"

noiseNNIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNNIHS =
  handshakeState
  (makeHSN "NN")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseKNIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKNIHS =
  handshakeState
  (makeHSN "KN")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseKNI0)

noiseNKIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNKIHS =
  handshakeState
  (makeHSN "NK")
  Nothing
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseNKI0)

noiseKKIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKKIHS =
  handshakeState
  (makeHSN "KK")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseKKI0)

noiseNEIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNEIHS =
  handshakeState
  (makeHSN "NE")
  Nothing
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  (Just noiseNEI0)

noiseKEIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKEIHS =
  handshakeState
  (makeHSN "KE")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  (Just noiseKEI0)

noiseNXIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNXIHS =
  handshakeState
  (makeHSN "NX")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseKXIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKXIHS =
  handshakeState
  (makeHSN "KX")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseKXI0)

noiseXNIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXNIHS =
  handshakeState
  (makeHSN "XN")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseINIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseINIHS =
  handshakeState
  (makeHSN "IN")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseXKIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXKIHS =
  handshakeState
  (makeHSN "XK")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseXKI0)

noiseIKIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIKIHS =
  handshakeState
  (makeHSN "IK")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseIKI0)

noiseXEIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXEIHS =
  handshakeState
  (makeHSN "XE")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  (Just noiseXEI0)

noiseIEIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIEIHS =
  handshakeState
  (makeHSN "IE")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  (Just noiseIEI0)

noiseXXIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXXIHS =
  handshakeState
  (makeHSN "XX")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseIXIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIXIHS =
  handshakeState
  (makeHSN "IX")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseNIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNIHS =
  handshakeState
  (makeHSN "N")
  Nothing
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseNI0)

noiseKIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKIHS =
  handshakeState
  (makeHSN "K")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseKI0)

noiseXIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXIHS =
  handshakeState
  (makeHSN "X")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseXI0)

noiseNNRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNNRHS =
  handshakeState
  (makeHSN "NN")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseKNRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKNRHS =
  handshakeState
  (makeHSN "KN")
  Nothing
  Nothing
  (Just (snd initStatic))
  Nothing
  (Just noiseKNR0)

noiseNKRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNKRHS =
  handshakeState
  (makeHSN "NK")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseNKR0)

noiseKKRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKKRHS =
  handshakeState
  (makeHSN "KK")
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing
  (Just noiseKKR0)

noiseNERHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNERHS =
  handshakeState
  (makeHSN "NE")
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  (Just noiseNER0)

noiseKERHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKERHS =
  handshakeState
  (makeHSN "KE")
  (Just respStatic)
  (Just respEphemeral)
  (Just (snd initStatic))
  Nothing
  (Just noiseKER0)

noiseNXRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNXRHS =
  handshakeState
  (makeHSN "NX")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseKXRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKXRHS =
  handshakeState
  (makeHSN "KX")
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing
  (Just noiseKXR0)

noiseXNRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXNRHS =
  handshakeState
  (makeHSN "XN")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseINRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseINRHS =
  handshakeState
  (makeHSN "IN")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseXKRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXKRHS =
  handshakeState
  (makeHSN "XK")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseXKR0)

noiseIKRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIKRHS =
  handshakeState
  (makeHSN "IK")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseIKR0)

noiseXERHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXERHS =
  handshakeState
  (makeHSN "XE")
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  (Just noiseXER0)

noiseIERHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIERHS =
  handshakeState
  (makeHSN "IE")
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  (Just noiseIER0)

noiseXXRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXXRHS =
  handshakeState
  (makeHSN "XX")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseIXRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIXRHS =
  handshakeState
  (makeHSN "IX")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseNRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNRHS =
  handshakeState
  (makeHSN "N")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseNR0)

noiseKRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKRHS =
  handshakeState
  (makeHSN "K")
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing
  (Just noiseKR0)

noiseXRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXRHS =
  handshakeState
  (makeHSN "X")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseXR0)
