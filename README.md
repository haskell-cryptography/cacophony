# cacophony

[![Build Status](https://travis-ci.org/centromere/cacophony.svg?branch=master)](https://travis-ci.org/centromere/cacophony)
[![Haskell](http://b.repl.ca/v1/language-haskell-blue.png)](http://www.haskell.org)

This library implements the [Noise](https://github.com/trevp/noise/blob/master/noise.md) protocol.

## Basic usage

1. Import the modules for the kind of handshake you'd like to use.

   For example, if you want to use `Noise_IK_25519_AESGCM_SHA256`, your imports would be:
   ```haskell
   import Control.Lens

   import Crypto.Noise
   import Crypto.Noise.Cipher.AESGCM
   import Crypto.Noise.DH
   import Crypto.Noise.DH.Curve25519
   import Crypto.Noise.Hash.SHA256
   import Crypto.Noise.HandshakePatterns (noiseIK)
   ```

2. Set the handshake parameters.

   Select a handshake pattern to use. Patterns are defined in the `Crypto.Noise.HandshakePatterns` module.
   Ensure that you provide the keys which are required by the handshake pattern you choose. For example,
   the `Noise_IK` pattern requires that the initiator provides a local static key and a remote static key,
   while the responder is only responsible for a local static key. You can use `defaultHandshakeOpts` to
   return a default set of options in which the prologue is an empty string, PSKs are disabled, and all
   keys are set to `Nothing`. You must set the local ephemeral key for all handshake patterns, and it
   should never be reused.

   Functions for manipulating DH keys can be found in the `Crypto.Noise.DH` module.

   ```haskell
   -- Initiator
   local_ephemeral_key <- dhGenKey :: IO (KeyPair Curve25519)

   let dho = defaultHandshakeOpts noiseIK InitiatorRole :: HandshakeOpts Curve25519
        iho = dho & hoPrologue          .~ "prologue"
                  & hoPreSharedKey      .~ Just "pre-shared-key"
                  & hoLocalStaticKey    .~ Just local_static_key
                  & hoLocalEphemeralKey .~ Just local_ephemeral_key
                  & hoRemoteStaticKey   .~ Just remote_static_key -- communicated out-of-band

   -- Responder
   local_ephemeral_key <- dhGenKey :: IO (KeyPair Curve25519)

   let dho = defaultHandshakeOpts noiseIK ResponderRole :: HandshakeOpts Curve25519
        rho = dho & hoPrologue          .~ "prologue"
                  & hoPreSharedKey      .~ Just "pre-shared-key"
                  & hoLocalStaticKey    .~ Just local_static_key
                  & hoLocalEphemeralKey .~ Just local_ephemeral_key
   ```

3. Create the Noise state.
   ```haskell
   -- Initiator
   let ins = noiseState iho :: NoiseState AESGCM Curve25519 SHA256

   -- Responder
   let rns = noiseState rho :: NoiseState AESGCM Curve25519 SHA256
   ```

4. Send and receive messages.
   ```haskell
   -- Initiator
   let writeResult         = writeMessage ins "They must find it difficult -- those who have taken authority as the truth, rather than truth as the authority."
        (ciphertext, ins')  = either (error "something terrible happened") id writeResult

   -- Responder
   let readResult          = readMessage rns ciphertext
        (plaintext, rns')   = either (error "something terrible happened") id readResult
   ```

   **Ensure that you never re-use a noise state to send more than one message.**

   Decrypted messages are stored internally as `ScrubbedBytes` and will be wiped from memory when they are
   destroyed. Helper functions for dealing with `ScrubbedBytes` can be found in the `Data.ByteArray.Extend` module.

### Helper functions

The following functions are found in `Crypto.Noise` and can be helpful when designing an application which uses
Noise:

  * `remoteStaticKey` -- For handshake patterns where the remote party's static key is transmitted, this function
    can be used to retrieve it. This allows for the creation of public key-based access-control lists.

  * `handshakeComplete` -- Returns `True` if the handshake is complete.

  * `sessionId` -- Retrieves the `h` value associated with the conversation's SymmetricState. This value is intended
    to be used for channel binding. For example, the initiator might cryptographically sign this value as part of
    some higher-level authentication scheme.

## Vectors

Test vectors can be generated and verified using the `vectors` program. It accepts no arguments. When run,
it will check for the existence of `vectors/cacophony.txt` within the current working directory. If it is not
found, it is generated. If it is found, it is verified. All files within the `vectors/` directory (regardless
of their name) are also verified.

The generated vectors are minified JSON. There is a small python script within the `tools/` directory that
formats the JSON-blob in to something more readable.

## Example code

An echo-server and echo-client are located within the `examples/` directory. The binary protocol they use to
communicate is as follows:
```
C -> S: [psk byte] [pattern byte] [cipher byte] [dh byte] [hash byte]
C -> S: [num message bytes (uint16 big endian)] [message]
S -> C: [num message bytes (uint16 big endian)] [message]
...
```

where `message` is any raw Noise handshake or message data.

For these example programs, the server chooses the value of the PSK, and the client chooses whether or not
to use a PSK-enabled handshake. When starting the server, if the PSK is unspecified it defaults to the
string "They Live".

To include these examples in your build, pass the -fbuild-examples flag to Cabal.

### Byte definitions

| byte | psk      | pattern | cipher     | dh    | hash    |
|------|----------|---------|------------|-------|---------|
| 0x00 | disabled | NN      | ChaChaPoly | 25519 | SHA256  |
| 0x01 | enabled  | KN      | AESGCM     | 448   | SHA512  |
| 0x02 |          | NK      |            |       | BLAKE2s |
| 0x03 |          | KK      |            |       | BLAKE2b |
| 0x04 |          | NX      |            |       |         |
| 0x05 |          | KX      |            |       |         |
| 0x06 |          | XN      |            |       |         |
| 0x07 |          | IN      |            |       |         |
| 0x08 |          | XK      |            |       |         |
| 0x09 |          | IK      |            |       |         |
| 0x0a |          | XX      |            |       |         |
| 0x0b |          | IX      |            |       |         |
| 0x0c |          | XR      |            |       |         |
