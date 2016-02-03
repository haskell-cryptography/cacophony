# cacophony

[![Build Status](https://travis-ci.org/centromere/cacophony.svg?branch=master)](https://travis-ci.org/centromere/cacophony)
[![Haskell](http://b.repl.ca/v1/language-haskell-blue.png)](http://www.haskell.org)

This library implements the [Noise](https://github.com/trevp/noise/blob/master/noise.md) protocol.

## Basic usage

1. Define functions which will be called when protocol messages are to be read and written to the remote peer.
   The payloadIn and payloadOut functions are called when payloads are received and needed.
   ```haskell
   writeMsg   :: ByteString -> IO ()
   readMsg    :: IO ByteString
   payloadIn  :: Plaintext -> IO ()
   payloadOut :: IO Plaintext
   -- If you don't need to use payloads, do the following:
   let hc = HandshakeCallbacks (writeMsg socket)
                                (readMsg socket)
                                (\_ -> return ())
                                (return "")
   ```

2. Create the handshake state:
   Select a handshake pattern to use. Patterns are defined in the Crypto.Noise.HandshakePatterns module.
   Ensure that you provide the keys which are required by the handshake pattern you choose. For example,
   the Noise\_IK pattern requires that the initiator provides a local static key and a remote static key.
   Remote keys are communicated out-of-band.
   ```haskell
   let hs = handshakeState $ HandshakeStateParams
      noiseIK
      ""
      -- ^ Prologue
      (Just "foo")
      -- ^ Pre-shared key
      (Just initStatic)
      -- ^ Local static key
      Nothing
      -- ^ Local ephemeral key
      (Just (snd respStatic))
      -- ^ Remote static key
      Nothing
      -- ^ Remote ephemeral key
      True
      -- ^ True if we are initiator
   ```

3. Run the handshake:
   ```haskell
   (encryptionCipherState, decryptionCipherState) <- runHandshake hs hc
   ```

4. Send and receive transport messages:
   ```haskell
   let (cipherText, encryptionCipherState') = encryptPayload "hello world" encryptionCipherState
   let (Plaintext pt, decryptionCipherState') = decryptPayload msg decryptionCipherState
   ```
   Ensure that you never re-use a cipher state with encryptPayload and decryptPayload.
