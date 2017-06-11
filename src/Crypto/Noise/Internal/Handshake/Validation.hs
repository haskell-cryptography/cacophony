{-# LANGUAGE TemplateHaskell #-}
----------------------------------------------------------------
-- |
-- Module      : Crypto.Noise.Internal.Handshake.Validation
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX
module Crypto.Noise.Internal.Handshake.Validation where

import Control.Applicative.Free
import Control.Lens
import Control.Monad (when)
import Control.Monad.State

import Crypto.Noise.Internal.Handshake.Pattern

type ErrorPosition = (Int, Int)

data InspectionError
  = InitMultipleETokens ErrorPosition
  | InitMultipleSTokens ErrorPosition
  | RespMultipleETokens ErrorPosition
  | RespMultipleSTokens ErrorPosition
  | InitSecretNotRandom ErrorPosition
  | RespSecretNotRandom ErrorPosition
  | DHInPreMsg          ErrorPosition
  | PSKInPreMsg         ErrorPosition
  | PSKWithoutEToken    ErrorPosition
  deriving Show

data Inspection = Inspection
  { _iInitESent    :: Bool
  , _iInitSSent    :: Bool
  , _iInitPSKSent  :: Bool
  , _iRespESent    :: Bool
  , _iRespSSent    :: Bool
  , _iRespPSKSent  :: Bool
  , _iInitRandReq  :: Bool
  , _iInitRandDone :: Bool
  , _iRespRandReq  :: Bool
  , _iRespRandDone :: Bool
  , _iCurTokenPos  :: Int
  , _iCurMsgPos    :: Int
  , _iErrors       :: [InspectionError]
  } deriving Show

$(makeLenses ''Inspection)

inspection :: Inspection
inspection = Inspection
  { _iInitESent    = False
  , _iInitSSent    = False
  , _iInitPSKSent  = False
  , _iRespESent    = False
  , _iRespSSent    = False
  , _iRespPSKSent  = False
  , _iInitRandReq  = False
  , _iInitRandDone = False
  , _iRespRandReq  = False
  , _iRespRandDone = False
  , _iCurTokenPos  = 0
  , _iCurMsgPos    = 0
  , _iErrors       = []
  }

verifyNotInPreMsg :: Message a -> State Inspection ()
verifyNotInPreMsg (PreInitiator _ _) = addError DHInPreMsg
verifyNotInPreMsg (PreResponder _ _) = addError DHInPreMsg
verifyNotInPreMsg (Initiator    _ _) = return ()
verifyNotInPreMsg (Responder    _ _) = return ()

verifyRandDoneIfReq :: Message a -> State Inspection ()
verifyRandDoneIfReq (Initiator _ _) = do
  initRandReq  <- use iInitRandReq
  initRandDone <- use iInitRandDone

  when (initRandReq && not initRandDone) $ addError InitSecretNotRandom

verifyRandDoneIfReq (Responder _ _) = do
  respRandReq  <- use iRespRandReq
  respRandDone <- use iRespRandDone

  when (respRandReq && not respRandDone) $ addError RespSecretNotRandom

verifyRandDoneIfReq _ = return ()

verifyESentIfPSK :: Message a -> State Inspection ()
verifyESentIfPSK (Initiator _ _) = do
  initESent   <- use iInitESent
  initPSKSent <- use iInitPSKSent

  when (initPSKSent && not initESent) $ addError PSKWithoutEToken

verifyESentIfPSK (Responder _ _) = do
  respESent   <- use iRespESent
  respPSKSent <- use iRespPSKSent

  when (respPSKSent && not respESent) $ addError PSKWithoutEToken

verifyESentIfPSK _ = return ()

continueToken :: a -> State Inspection a
continueToken next = iCurTokenPos %= (+ 1) >> return next

continueMsg :: a -> State Inspection a
continueMsg next = iCurTokenPos .= 0 >> iCurMsgPos %= (+ 1) >> return next

addError :: (ErrorPosition -> InspectionError) -> State Inspection ()
addError err = do
  msgPos   <- use iCurMsgPos
  tokenPos <- use iCurTokenPos
  iErrors <>= [err (msgPos, tokenPos)]

inspectToken :: Message m -> Token a -> State Inspection a
inspectToken m (E next) = do
  case m of
    PreInitiator _ _ -> checkInit
    PreResponder _ _ -> checkResp
    Initiator    _ _ -> checkInit
    Responder    _ _ -> checkResp

  continueToken next

  where
    checkInit = do
      initESent <- use iInitESent
      if initESent
        then addError InitMultipleETokens
        else iInitESent .= True

    checkResp = do
      respESent <- use iRespESent
      if respESent
        then addError RespMultipleETokens
        else iRespESent .= True

inspectToken m (S next) = do
  case m of
    PreInitiator _ _ -> checkInit
    PreResponder _ _ -> checkResp
    Initiator    _ _ -> checkInit
    Responder    _ _ -> checkResp

  continueToken next

  where
    checkInit = do
      initSSent <- use iInitSSent
      if initSSent
        then addError InitMultipleSTokens
        else iInitSSent .= True

    checkResp = do
      respSSent <- use iRespSSent
      if respSSent
        then addError RespMultipleSTokens
        else iRespSSent .= True

inspectToken m (Ee next) = do
  verifyNotInPreMsg m

  iInitRandDone .= True
  iRespRandDone .= True

  continueToken next

inspectToken m (Es next) = do
  verifyNotInPreMsg m

  iInitRandDone .= True
  iRespRandReq  .= True

  continueToken next

inspectToken m (Se next) = do
  verifyNotInPreMsg m

  iInitRandReq  .= True
  iRespRandDone .= True

  continueToken next

inspectToken m (Ss next) = do
  verifyNotInPreMsg m

  iInitRandReq .= True
  iRespRandReq .= True

  continueToken next

inspectToken m (Psk next) = do
  case m of
    PreInitiator _ _ -> addError PSKInPreMsg
    PreResponder _ _ -> addError PSKInPreMsg
    Initiator    _ _ -> iInitPSKSent .= True
    Responder    _ _ -> iRespPSKSent .= True

  continueToken next

inspectMessage :: Message a -> State Inspection a
inspectMessage m@(PreInitiator mp next) = do
  runAp (inspectToken m) mp
  continueMsg next

inspectMessage m@(PreResponder mp next) = do
  runAp (inspectToken m) mp
  continueMsg next

inspectMessage m@(Initiator mp next) = do
  runAp (inspectToken m) mp
  verifyRandDoneIfReq m
  verifyESentIfPSK m
  continueMsg next

inspectMessage m@(Responder mp next) = do
  runAp (inspectToken m) mp
  verifyRandDoneIfReq m
  verifyESentIfPSK m
  continueMsg next

validateHandshakePattern :: HandshakePattern -> [InspectionError]
validateHandshakePattern hp = execState (runAp inspectMessage $ hp ^. hpMsgSeq) inspection ^. iErrors
