{-# LANGUAGE RecordWildCards #-}
module Client where

import Control.Concurrent     (forkIO)
import Control.Monad          (void)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import Data.ByteString.Char8  (ByteString, putStrLn, pack, unpack)
import Data.Maybe             (fromMaybe, isJust)
import Data.Monoid            ((<>))
import Prelude hiding         (putStrLn)
import System.Console.Haskeline
import System.Exit            (exitFailure)

import Crypto.Noise
import Crypto.Noise.DH

import Options
import Pipe
import Socket
import Types

data HandshakeState
  = IncompleteWaitingOnUser
  | IncompleteWaitingOnPeer
  | Complete

printKeys :: DH d
          => KeyPair d
          -> KeyPair d
          -> IO ()
printKeys (epriv, epub) (spriv, spub) = do
  putStrLn "Your keys are as follows:"
  putStrLn $ "private ephemeral: " <> (B64.encode . convert . dhSecToBytes) epriv
  putStrLn $ "public  ephemeral: " <> (B64.encode . convert . dhPubToBytes) epub
  putStrLn $ "private static:    " <> (B64.encode . convert . dhSecToBytes) spriv
  putStrLn $ "public  static:    " <> (B64.encode . convert . dhPubToBytes) spub

genKeyIfNeeded :: DH d
               => DHType d
               -> Maybe ScrubbedBytes
               -> IO (KeyPair d)
genKeyIfNeeded _ Nothing  = dhGenKey
genKeyIfNeeded _ (Just k) =
  maybe (putStrLn ("error decoding key: " <> convert k) >> exitFailure)
        return
        (dhBytesToPair k)

genOpts :: DH d
        => DHType d
        -> HandshakeRole
        -> ScrubbedBytes
        -> HandshakeOpts d
genOpts _ = defaultHandshakeOpts

genNoiseState :: (Cipher c, DH d, Hash h)
              => CipherType c
              -> HashType h
              -> HandshakeOpts d
              -> HandshakePattern
              -> NoiseState c d h
genNoiseState _ _ = noiseState

handshakeLoop :: (Cipher c, DH d, Hash h)
        => (ByteString -> IO ())
        -> IO ByteString
        -> HandshakeState
        -> Bool
        -> NoiseState c d h
        -> InputT IO ()
handshakeLoop writeCb readCb IncompleteWaitingOnUser seenStatic state = do
  minput <- fmap (convert . pack) <$> getInputLine "payload> "

  case minput of
    Nothing    -> return ()
    Just input -> case writeMessage input state of
      NoiseResultMessage ct state' -> processCiphertext ct state'
      NoiseResultNeedPSK state' -> do
        pskResult <- pskLoop True state'
        case pskResult of
          Nothing            -> return ()
          Just (ct, state'') -> processCiphertext ct state''
      NoiseResultException ex      -> do
        outputStrLn $ "exception: " <> show ex
        handshakeLoop writeCb readCb IncompleteWaitingOnPeer seenStatic state

  where
    processCiphertext ct state' = do
      liftIO . writeCb . convert $ ct
      outputStrLn . unpack $ "sent: " <> (B16.encode . convert) ct

      if handshakeComplete state'
        then do
          outputStrLn "handshake complete!"
          outputStrLn . unpack $ "handshake hash: " <> (B16.encode . convert . handshakeHash) state'
          handshakeLoop writeCb readCb Complete seenStatic state'
        else handshakeLoop writeCb readCb IncompleteWaitingOnPeer seenStatic state'

handshakeLoop writeCb readCb IncompleteWaitingOnPeer seenStatic state = do
  outputStrLn "handshake incomplete, waiting for message from peer"
  response <- liftIO readCb

  outputStrLn . unpack $ "received: " <> B16.encode response

  case readMessage (convert response) state of
    NoiseResultMessage pt state' -> processPayload pt state'
    NoiseResultNeedPSK state'    -> do
      pskResult <- pskLoop False state'
      case pskResult of
        Nothing            -> return ()
        Just (pt, state'') -> processPayload pt state''

    NoiseResultException ex      -> do
      outputStrLn $ "exception: " <> show ex
      handshakeLoop writeCb readCb IncompleteWaitingOnPeer seenStatic state

  where
    processPayload pt ns = do
      outputStrLn . unpack $ "payload: " <> convert pt

      seenStatic' <- if not seenStatic
        then case remoteStaticKey ns of
          Nothing -> return False
          Just k  -> do
            let b64key = B64.encode . convert . dhPubToBytes $ k
            outputStrLn . unpack $ "static key received: " <> b64key
            return True
        else return True

      if handshakeComplete ns
        then do
          outputStrLn "handshake complete!"
          outputStrLn . unpack $ "handshake hash: " <> (B16.encode . convert . handshakeHash) ns
          handshakeLoop writeCb readCb Complete seenStatic' ns
        else handshakeLoop writeCb readCb IncompleteWaitingOnUser seenStatic' ns

handshakeLoop writeCb readCb Complete _ state = do
  ep <- getExternalPrint
  -- Note that the message loops do not share the NoiseState because
  -- they do not have to (CipherStates evolve independently of one
  -- another).
  void . liftIO . forkIO $ messageReadLoop readCb ep state
  messageWriteLoop writeCb state

messageWriteLoop :: (Cipher c, DH d, Hash h)
                 => (ByteString -> IO ())
                 -> NoiseState c d h
                 -> InputT IO ()
messageWriteLoop writeCb state = do
  minput <- fmap (convert . pack) <$> getInputLine "message> "
  case minput of
    Nothing    -> return ()
    Just input -> case writeMessage input state of
      NoiseResultMessage ct state' -> do
        liftIO . writeCb . convert $ ct
        outputStrLn . unpack $ "sent: " <> (B16.encode . convert) ct
        messageWriteLoop writeCb state'
      NoiseResultNeedPSK   _  -> return () -- this should never happen
      NoiseResultException ex -> do
        outputStrLn $ "exception: " <> show ex
        messageWriteLoop writeCb state

messageReadLoop :: (Cipher c, DH d, Hash h)
                => IO ByteString
                -> (String -> IO ())
                -> NoiseState c d h
                -> IO ()
messageReadLoop readCb printFunc state = do
  msg <- readCb
  printFunc . unpack $ "received: " <> B16.encode msg
  case readMessage (convert msg) state of
    NoiseResultMessage pt state' -> do
      printFunc . unpack $ "message:  " <> convert pt
      messageReadLoop readCb printFunc state'
    NoiseResultNeedPSK   _  -> return () -- this should never happen
    NoiseResultException ex -> do
      printFunc $ "exception: " <> show ex
      printFunc "re-reading with state unchanged"
      messageReadLoop readCb printFunc state

pskLoop :: (Cipher c, DH d, Hash h)
        => Bool
        -> NoiseState c d h
        -> InputT IO (Maybe (ScrubbedBytes, NoiseState c d h))
pskLoop write state = do
  minput <- fmap (convert . pack) <$> getInputLine "psk> "
  case minput of
    Nothing    -> return Nothing
    Just input -> case operation input state of
      NoiseResultMessage ct state' -> return . Just $ (ct, state')
      NoiseResultNeedPSK state'    -> pskLoop write state'
      NoiseResultException ex      -> do
        outputStrLn $ "exception: " <> show ex
        pskLoop write state

  where
    operation = if write then writeMessage else readMessage

genCallbacks :: Options
             -> IO (ByteString -> IO (), IO ByteString)
genCallbacks Options{..} =
  case (optLocalHost, optLocalPort, optRemoteHost, optRemotePort, optPipeCommand) of
    (Just lhost, Just lport, Just rhost, Just rport, _) ->
      genSocket lhost lport rhost rport
    (_, _, _, _, Just cmd) -> genPipe cmd
    _ -> error "this should never happen"

startClient :: Options
            -> IO ()
startClient opts@Options{..} = do
  let hsn      = fromMaybe (error "no handshake name") optHandshakeName
      role     = fromMaybe (error "no role")           optHandshakeRole
      prologue = fromMaybe (error "no prologue")       optHandshakePrologue

  case (hsCipher hsn, hsDH hsn, hsHash hsn) of
    (WrapCipherType c, WrapDHType d, WrapHashType h) -> do
      localEphemeral <- genKeyIfNeeded d optLocalEphemeral
      localStatic    <- genKeyIfNeeded d optLocalStatic
      printKeys localEphemeral localStatic

      let ho = setLocalEphemeral (Just localEphemeral)
               . setLocalStatic  (Just localStatic)
               . setRemoteStatic (dhBytesToPub =<< optRemoteStatic)
               $ genOpts d role prologue
          ns = genNoiseState c h ho (patternToHandshake . hsPatternName $ hsn)
          op = if role == InitiatorRole then IncompleteWaitingOnUser else IncompleteWaitingOnPeer

      (writeCb, readCb) <- genCallbacks opts
      runInputT defaultSettings $ handshakeLoop writeCb readCb op (isJust optRemoteStatic) ns
