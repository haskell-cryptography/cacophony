# cacophony

[![Build Status](https://travis-ci.org/centromere/cacophony.svg?branch=master)](https://travis-ci.org/centromere/cacophony)
[![Haskell](http://b.repl.ca/v1/language-haskell-blue.png)](http://www.haskell.org)

This library implements the [Noise](https://github.com/trevp/noise/blob/master/noise.md) protocol.

## Basic usage

1. Import the modules for the kind of handshake you'd like to use.

   For example, if you want to use `Noise_IK_25519_AESGCM_SHA256`, your imports would be:
   ```haskell
   import Crypto.Noise.Cipher.AESGCM
   import Crypto.Noise.Curve.Curve25519
   import Crypto.Noise.Hash.SHA256
   import Crypto.Noise.Handshake
   import Crypto.Noise.HandshakePatterns (noiseIK)
   ```

2. Define the functions that will be called during various stages of the handshake.
   ```haskell
   writeMsg   :: ByteString -> IO ()
   readMsg    :: IO ByteString
   payloadIn  :: Plaintext -> IO ()
   payloadOut :: IO Plaintext
   staticIn   :: PublicKey d -> IO Bool
   ```

   `writeMsg` and `readMsg` will typically be functions that write to and read from a socket.

   The `payloadIn` and `payloadOut` functions are called when payloads are received and needed.

   The `staticIn` function is called when a static key is received from the remote peer.
   If this function returns `False`, the handshake is immediately aborted. Otherwise, it
   continues normally. See the documentation of `HandshakeCallbacks` for details.

   If you don't need to use payloads and want to accept all remote static keys, do the following:
   ```haskell
   let hc = HandshakeCallbacks (writeMsg socket)
                                (readMsg socket)
                                (\_ -> return ())
                                (return "")
                                (\_ -> return True)
   ```

3. Create the handshake state.

   Select a handshake pattern to use. Patterns are defined in the `Crypto.Noise.HandshakePatterns` module.
   Ensure that you provide the keys which are required by the handshake pattern you choose. For example,
   the `Noise_IK` pattern requires that the initiator provides a local static key and a remote static key.
   Remote keys are communicated out-of-band.
   ```haskell
   let initiatorState = handshakeState $ HandshakeOpts
      noiseIK
      "prologue"
      (Just "pre-shared-key")
      (Just local_static_key)
      Nothing                  -- local ephemeral key
      (Just remote_static_key) -- communicated out-of-band
      Nothing                  -- remote ephemeral key
      True                     -- we are the initiator
   ```

   ```haskell
   let responderState = handshakeState $ HandshakeOpts
      noiseIK
      "prologue"
      (Just "pre-shared-key")
      (Just local_static_key)
      Nothing -- local ephemeral key
      Nothing -- we don't know their static key yet
      Nothing -- remote ephemeral key
      False   -- we are the responder
   ```

4. Run the handshake:
   ```haskell
   (encryptionCipherState, decryptionCipherState) <- runHandshake initiatorState hc
   ```

   ```haskell
   (encryptionCipherState, decryptionCipherState) <- runHandshake responderState hc
   ```

5. Send and receive transport messages:
   ```haskell
   let (cipherText, encryptionCipherState') = encryptPayload "hello world" encryptionCipherState
   ```

   ```haskell
   let (Plaintext pt, decryptionCipherState') = decryptPayload msg decryptionCipherState
   ```

   Ensure that you never re-use a cipher state.

## Example code

An echo-server and echo-client are located within the `examples/` directory. The binary protocol is as follows:
```
C -> S: [pattern byte] [cipher byte] [curve byte] [hash byte]
C -> S: [num bytes (uint16 big endian)] [message]
S -> C: [num bytes (uint16 big endian)] [message]
...
```

`message` is any raw Noise handshake or message data.

### Byte definitions

| byte | pattern | cipher     | curve | hash    |
|------|---------|------------|-------|---------|
| 0    | NN      | ChaChaPoly | 25519 | SHA256  |
| 1    | KN      | AESGCM     | 448   | SHA512  |
| 2    | NK      |            |       | BLAKE2s |
| 3    | KK      |            |       | BLAKE2b |
| 4    | NX      |            |       |         |
| 5    | KX      |            |       |         |
| 6    | XN      |            |       |         |
| 7    | IN      |            |       |         |
| 8    | XK      |            |       |         |
| 9    | IK      |            |       |         |
| a    | XX      |            |       |         |
| b    | IX      |            |       |         |
| c    | XR      |            |       |         |
