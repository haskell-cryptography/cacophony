{-# LANGUAGE OverloadedStrings, TypeApplications #-}
module Main where

import Prelude hiding (replicate, length, concat, splitAt)
import Crypto.Noise (NoiseState, NoiseResult(..), ScrubbedBytes, HandshakeOpts, writeMessage, readMessage, nsReceivingCipherState, nsSendingCipherState, csn, csk, ssck, nsHandshakeState, hsSymmetricState, noiseState, setLocalEphemeral, setLocalStatic, setRemoteStatic, defaultHandshakeOpts, HandshakeRole(..))
import Crypto.Noise.Cipher.ChaChaPoly1305 (ChaChaPoly1305)
import Crypto.Noise.DH (KeyPair, dhBytesToPair)
import Crypto.Noise.DH.Secp256k1 (Secp256k1)
import Crypto.Noise.Hash.SHA256 (SHA256)
import Crypto.Noise.HandshakePatterns (noiseXK)
import Crypto.Noise.Cipher (cipherBytesToSym, cipherSymToBytes, cipherZeroNonce)
import Data.ByteString.Base16 (encode, decode)
import Data.ByteArray (convert, length)
import Data.ByteString (ByteString, pack, concat, splitAt)
import Control.Monad (unless, foldM)
import Control.Lens
import Crypto.Noise.Hash (hashBytesToCK, hashHKDF)
import Data.Bits (shiftR)
import Data.Maybe (fromJust, isNothing)

hexToPair :: ByteString -> KeyPair Secp256k1
hexToPair x = fromJust $ dhBytesToPair $ convert $ fst $ decode x

ilocalStaticKey = hexToPair "1111111111111111111111111111111111111111111111111111111111111111"
(sec, iremoteStaticKey) = hexToPair "2121212121212121212121212121212121212121212121212121212121212121"

test_handshake = do
  -- see
  -- https://github.com/cdecker/lightning/blob/pywire/contrib/pyln-proto/tests/test_wire.py#L29
  -- which uses values from
  -- https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#initiator-tests
  let ilocalEphemeralKey = hexToPair "1212121212121212121212121212121212121212121212121212121212121212"

  -- Initiator
  let idho = defaultHandshakeOpts InitiatorRole "lightning" :: HandshakeOpts Secp256k1
      iiho = setLocalStatic      (Just ilocalStaticKey)
            . setLocalEphemeral (Just ilocalEphemeralKey)
            . setRemoteStatic   (Just iremoteStaticKey) -- communicated out-of-band
            $ idho

  -- Responder
  let rlocalEphemeralKey = hexToPair "2222222222222222222222222222222222222222222222222222222222222222"

  let rdho = defaultHandshakeOpts ResponderRole "lightning" :: HandshakeOpts Secp256k1
      rrho = setLocalStatic      (Just (sec, iremoteStaticKey))
            . setLocalEphemeral (Just rlocalEphemeralKey)
            $ rdho

  -- Initiator
  let ins = noiseState iiho noiseXK :: NoiseState ChaChaPoly1305 Secp256k1 SHA256

  -- Responder
  let rns = noiseState rrho noiseXK :: NoiseState ChaChaPoly1305 Secp256k1 SHA256

  let writeResult = writeMessage "" ins
  let NoiseResultMessage ciphertext ins = writeResult
  --putStrLn $ "Main.hs ciphertext: " ++ (show $ encode $ convert $ ciphertext)
  let readResult = readMessage ciphertext rns
  -- note how version byte is missing
  unless (ciphertext == convert (fst $ decode "036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a")) (error "act1")
  let NoiseResultMessage plaintext rns = readResult
  --putStrLn $ "act one received: " ++ (show $ (convert $ plaintext :: ByteString))
  let writeActTwoResult = writeMessage "" rns
  let NoiseResultMessage ciphertext rns = writeActTwoResult
  -- note how version byte is missing
  unless (ciphertext == convert (fst $ decode "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae")) $ error "act2"

  let readActTwoResult = readMessage ciphertext ins
  let NoiseResultMessage plaintext ins = readActTwoResult

  -- note how we are not sending the public key like in the python code linked
  -- -- dhPubToBytes $ snd $ ilocalStaticKey
  let writeActThreeResult = writeMessage "" ins
  let NoiseResultMessage ciphertext ins = writeActThreeResult
  -- note how version byte is missing
  unless (ciphertext == convert (fst $ decode "b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba")) $ error $ "act3: " ++ show (encode $ convert ciphertext)

  let readActThreeResult = readMessage ciphertext rns
  let NoiseResultMessage plaintext rns = readActThreeResult
  putStrLn $ "act three received: " ++ show (encode $ convert plaintext)

  let msgtowrite = "\x68\x65\x6c\x6c\x6f"

  (lastm, ins) <- sendLnMsg msgtowrite ins
  unless (lastm == convert (fst $ decode "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95")) $ error $ "wrong msg1: " ++ show (encode $ convert lastm)

  (lastm, ins) <- foldM (\(_lastm, tins) _ -> do
    (m2, newins) <- sendLnMsg msgtowrite tins
    return (m2, newins)
    ) ("", ins) [1..498]

  unless (lastm == convert (fst $ decode "c95576afee4591869808a1c28e1fc7e5a578d86e569e1680e017b4f7a4df74ba222cf08e4ab8b1")) $ error $ "wrong msg2: " ++ show (encode $ convert lastm)

  (lastm, ins) <- sendLnMsg msgtowrite ins
  unless (lastm == convert (fst $ decode "0b0b7c16d2930e64a2db554f211f3bb279bf29701642655ce87e168ac0c6a19cdfe2b631d9e580")) $ error $ "wrong msg3: " ++ show (encode $ convert lastm)

  --putStrLn $ "handshake cipherstate" ++ (show $ fmap (encode . convert . cipherSymToBytes) $ ins ^? nsHandshakeState . hsSymmetricState . ssCipher . csk . _Just)
  --putStrLn $ "handshake ssh left" ++ (show $ fmap (encode . convert) $ ins ^? nsHandshakeState . hsSymmetricState . ssh . _Left)
  --putStrLn $ "handshake ssh right" ++ (show $ fmap (encode . convert . hashToBytes) $ ins ^? nsHandshakeState . hsSymmetricState . ssh . _Right)
  --putStrLn $ "handshake chaining key" ++ (show $ fmap (encode . convert . hashCKToBytes) $ ins ^? nsHandshakeState . hsSymmetricState . ssck)
  --putStrLn $ "nonce" ++ (show $ fmap (encode . convert . nonceToBytes) $ ins ^? nsSendingCipherState . _Just . csn)
  --putStrLn $ "sending symmetric key" ++ (show $ fmap (encode . convert . cipherSymToBytes) $ ins ^? nsSendingCipherState . _Just . csk . _Just)
  --putStrLn $ "receiving symmetric key" ++ (show $ fmap (encode . convert . cipherSymToBytes) $ ins ^? nsReceivingCipherState . _Just . csk . _Just)

  Just cipherstate <- pure $ ins ^. nsSendingCipherState
  let ssckb = ins ^. nsHandshakeState . hsSymmetricState . ssck
  let Just initialCskb = cipherstate ^. csk
  let [ck, k] = hashHKDF ssckb (cipherSymToBytes initialCskb) 2
  ins <- pure $ ins & nsHandshakeState . hsSymmetricState . ssck %~ const (hashBytesToCK ck)
  unless (k == convert (fst $ decode "3fbdc101abd1132ca3a0ae34a669d8d9ba69a587e0bb4ddd59524541cf4813d8")) $ error "couldn't calculate sk"
  let newcsk = Just $ cipherBytesToSym @ChaChaPoly1305 k
  cipherstate <- pure $ cipherstate & csk %~ const newcsk
  cipherstate <- pure $ cipherstate & csn %~ const cipherZeroNonce
  ins <- pure $ ins & nsSendingCipherState %~ const (Just cipherstate)

  (lastm, ins) <- sendLnMsg msgtowrite ins
  unless (lastm == convert (fst $ decode "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8")) $ error $ "wrong msg4: " ++ show (encode $ convert lastm)

  (lastm, ins) <- foldM (\(_lastm, tins) _ -> do
    (m2, newins) <- sendLnMsg msgtowrite tins
    return (m2, newins)
    ) ("", ins) [1..499]

  Just cipherstate <- pure $ ins ^. nsSendingCipherState
  let Just cskb = cipherstate ^. csk
  [ck, k] <- pure $ hashHKDF @SHA256 (ins ^. nsHandshakeState . hsSymmetricState . ssck) (cipherSymToBytes cskb) 2
  ins <- pure $ ins & nsHandshakeState . hsSymmetricState . ssck %~ const (hashBytesToCK ck)
  let newcsk = Just $ cipherBytesToSym @ChaChaPoly1305 k
  cipherstate <- pure $ cipherstate & csk %~ const newcsk
  cipherstate <- pure $ cipherstate & csn %~ const cipherZeroNonce
  ins <- pure $ ins & nsSendingCipherState %~ const (Just cipherstate)

  (lastm, ins) <- sendLnMsg msgtowrite ins
  unless (lastm == convert (fst $ decode "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09")) $ error $ "wrong msg5: " ++ show (encode $ convert lastm)

  -- OTHER DIRECTION! check that chaining_key is not shared between send/receive

  (lastm, rns) <- sendLnMsg msgtowrite rns
  unless (lastm == convert (fst $ decode "5bed0e4d7e2bc28afff2c05dd8fd7a24da81dc17be87e87504e5266a5301529467b98884e0b269")) $ error $ "wrong msg6: " ++ show (encode $ convert lastm)

  (lastm, rns) <- foldM (\(_lastm, trns) _ -> do
    (m2, newrns) <- sendLnMsg msgtowrite trns
    return (m2, newrns)
    ) ("", rns) [1..499]

  print $ encode $ convert lastm

  -- we'll pretend r has sent a lot of messages and needs to rotate now
  Just cipherstate <- pure $ rns ^. nsSendingCipherState
  let Just cskb = cipherstate ^. csk
  [ck, k] <- pure $ hashHKDF @SHA256 (rns ^. nsHandshakeState . hsSymmetricState . ssck) (cipherSymToBytes cskb) 2
  rns <- pure $ rns & nsHandshakeState . hsSymmetricState . ssck %~ const (hashBytesToCK ck)
  let newcsk = Just $ cipherBytesToSym @ChaChaPoly1305 k
  cipherstate <- pure $ cipherstate & csk %~ const newcsk
  cipherstate <- pure $ cipherstate & csn %~ const cipherZeroNonce
  rns <- pure $ rns & nsSendingCipherState %~ const (Just cipherstate)

  (lastm, rns) <- sendLnMsg msgtowrite rns
  unless (lastm == convert (fst $ decode "bfd031ec37bfd43f29401e2c5a465256ec7efe5258e70d7b0271200afd24239f7d3adc01e0be1f")) $ error $ "wrong msg7: " ++ show (encode $ convert lastm)

  let (p1, p2) = splitAt 18 $ convert lastm

  Just cipherstate <- pure $ ins ^. nsReceivingCipherState
  let Just cskb = cipherstate ^. csk
  [ck, k] <- pure $ hashHKDF @SHA256 ssckb (cipherSymToBytes cskb) 2
  ins <- pure $ ins & nsHandshakeState . hsSymmetricState . ssck %~ const (hashBytesToCK ck)
  let newcsk = Just $ cipherBytesToSym @ChaChaPoly1305 k
  cipherstate <- pure $ cipherstate & csk %~ const newcsk
  cipherstate <- pure $ cipherstate & csn %~ const cipherZeroNonce
  ins <- pure $ ins & nsReceivingCipherState %~ const (Just cipherstate)

  NoiseResultMessage plain_len ins <- pure $ readMessage (convert p1) ins
  NoiseResultMessage plain_msg ins <- pure $ readMessage (convert p2) ins
  return ()

i2osp :: Int -> ByteString
i2osp a =
    pack [firstByte, secondByte]
  where
    firstByte = fromIntegral $ a `shiftR` 8
    secondByte = fromIntegral a

sendLnMsg :: ScrubbedBytes -> NoiseState ChaChaPoly1305 Secp256k1 SHA256 -> IO (ScrubbedBytes, NoiseState ChaChaPoly1305 Secp256k1 SHA256)
sendLnMsg msg ins = do
  let lenBytes = convert $ i2osp $ length msg
  NoiseResultMessage lengthPart ins <- pure $ writeMessage lenBytes ins
  NoiseResultMessage msgPart ins <- pure $ writeMessage msg ins
  pure (convert $ concat [convert lengthPart, convert msgPart], ins)

test_bytesToPair :: IO ()
test_bytesToPair = do
  putStrLn $ "private key zero should be rejected" ++ show (isNothing $ dhBytesToPair @Secp256k1 $ convert $ pack [0])
  return ()

main = do
  test_handshake
  test_bytesToPair
