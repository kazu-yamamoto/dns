{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE CPP #-}
module Network.DNS.StateBinary (
    PState(..)
  , initialState
  , SPut
  , runSPut
  , put8
  , put16
  , put32
  , putInt8
  , putInt16
  , putInt32
  , putByteString
  , SGet
  , runSGet
  , runSGetAt
  , runSGetWithLeftovers
  , runSGetWithLeftoversAt
  , get8
  , get16
  , get32
  , getInt8
  , getInt16
  , getInt32
  , getNByteString
  , getPosition
  , getInput
  , getAtTime
  , wsPop
  , wsPush
  , wsPosition
  , addPositionW
  , push
  , pop
  , getNBytes
  ) where

import Control.Monad.State (State, StateT)
import qualified Control.Monad.State as ST
import qualified Data.Attoparsec.ByteString as A
import qualified Data.Attoparsec.Types as T
import qualified Data.ByteString as BS
import Data.ByteString.Builder (Builder)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.IntMap (IntMap)
import qualified Data.IntMap as IM
import Data.Map (Map)
import qualified Data.Map as M
import Data.Semigroup as Sem

import Network.DNS.Imports
import Network.DNS.Types

----------------------------------------------------------------

type SPut = State WState Builder

data WState = WState {
    wsDomain :: Map Domain Int
  , wsPosition :: Int
}

initialWState :: WState
initialWState = WState M.empty 0

instance Sem.Semigroup SPut where
    p1 <> p2 = (Sem.<>) <$> p1 <*> p2

instance Monoid SPut where
    mempty = return mempty
#if !(MIN_VERSION_base(4,11,0))
    mappend = (Sem.<>)
#endif

put8 :: Word8 -> SPut
put8 = fixedSized 1 BB.word8

put16 :: Word16 -> SPut
put16 = fixedSized 2 BB.word16BE

put32 :: Word32 -> SPut
put32 = fixedSized 4 BB.word32BE

putInt8 :: Int -> SPut
putInt8 = fixedSized 1 (BB.int8 . fromIntegral)

putInt16 :: Int -> SPut
putInt16 = fixedSized 2 (BB.int16BE . fromIntegral)

putInt32 :: Int -> SPut
putInt32 = fixedSized 4 (BB.int32BE . fromIntegral)

putByteString :: ByteString -> SPut
putByteString = writeSized BS.length BB.byteString

addPositionW :: Int -> State WState ()
addPositionW n = do
    (WState m cur) <- ST.get
    ST.put $ WState m (cur+n)

fixedSized :: Int -> (a -> Builder) -> a -> SPut
fixedSized n f a = do addPositionW n
                      return (f a)

writeSized :: (a -> Int) -> (a -> Builder) -> a -> SPut
writeSized n f a = do addPositionW (n a)
                      return (f a)

wsPop :: Domain -> State WState (Maybe Int)
wsPop dom = do
    doms <- ST.gets wsDomain
    return $ M.lookup dom doms

wsPush :: Domain -> Int -> State WState ()
wsPush dom pos = do
    (WState m cur) <- ST.get
    ST.put $ WState (M.insert dom pos m) cur

----------------------------------------------------------------

type SGet = StateT PState (T.Parser ByteString)

data PState = PState {
    psDomain :: IntMap Domain
  , psPosition :: Int
  , psInput :: ByteString
  , psAtTime  :: Int64
  }

----------------------------------------------------------------

getPosition :: SGet Int
getPosition = ST.gets psPosition

getInput :: SGet ByteString
getInput = ST.gets psInput

getAtTime :: SGet Int64
getAtTime = ST.gets psAtTime

addPosition :: Int -> SGet ()
addPosition n = do
    PState dom pos inp t <- ST.get
    ST.put $ PState dom (pos + n) inp t

push :: Int -> Domain -> SGet ()
push n d = do
    PState dom pos inp t <- ST.get
    ST.put $ PState (IM.insert n d dom) pos inp t

pop :: Int -> SGet (Maybe Domain)
pop n = ST.gets (IM.lookup n . psDomain)

----------------------------------------------------------------

get8 :: SGet Word8
get8  = ST.lift A.anyWord8 <* addPosition 1

get16 :: SGet Word16
get16 = ST.lift getWord16be <* addPosition 2
  where
    word8' = fromIntegral <$> A.anyWord8
    getWord16be = do
        a <- word8'
        b <- word8'
        return $ a * 0x100 + b

get32 :: SGet Word32
get32 = ST.lift getWord32be <* addPosition 4
  where
    word8' = fromIntegral <$> A.anyWord8
    getWord32be = do
        a <- word8'
        b <- word8'
        c <- word8'
        d <- word8'
        return $ a * 0x1000000 + b * 0x10000 + c * 0x100 + d

getInt8 :: SGet Int
getInt8 = fromIntegral <$> get8

getInt16 :: SGet Int
getInt16 = fromIntegral <$> get16

getInt32 :: SGet Int
getInt32 = fromIntegral <$> get32

----------------------------------------------------------------

getNBytes :: Int -> SGet [Int]
getNBytes len = toInts <$> getNByteString len
  where
    toInts = map fromIntegral . BS.unpack

getNByteString :: Int -> SGet ByteString
getNByteString n = ST.lift (A.take n) <* addPosition n

----------------------------------------------------------------

-- | To get a broad range of correct RRSIG inception and expiration times
-- without over or underflow, we choose a time half way between midnight PDT
-- 2010-07-15 (the day the root zone was signed) and 2^32 seconds later on
-- 2146-08-21.  Since 'decode' and 'runSGet' are pure, we can't peek at the
-- current time while parsing.  Outside this date range the output is off by
-- some non-zero multiple 2\^32 seconds.
--
dnsTimeMid :: Int64
dnsTimeMid = 3426660848

initialState :: Int64 -> ByteString -> PState
initialState t inp = PState IM.empty 0 inp t

runSGetAt :: Int64 -> SGet a -> ByteString -> Either DNSError (a, PState)
runSGetAt t parser inp =
    toResult $ A.parse (ST.runStateT parser $ initialState t inp) inp
  where
    toResult :: A.Result r -> Either DNSError r
    toResult (A.Done _ r)        = Right r
    toResult (A.Fail _ _ msg)    = Left $ DecodeError msg
    toResult (A.Partial _)       = Left $ DecodeError "incomplete input"

runSGet :: SGet a -> ByteString -> Either DNSError (a, PState)
runSGet = runSGetAt dnsTimeMid

runSGetWithLeftoversAt :: Int64      -- ^ Reference time for DNS clock arithmetic
                       -> SGet a     -- ^ Parser
                       -> ByteString -- ^ Encoded message
                       -> Either DNSError ((a, PState), ByteString)
runSGetWithLeftoversAt t parser inp =
    toResult $ A.parse (ST.runStateT parser $ initialState t inp) inp
  where
    toResult :: A.Result r -> Either DNSError (r, ByteString)
    toResult (A.Done     i r) = Right (r, i)
    toResult (A.Partial  f)   = toResult $ f BS.empty
    toResult (A.Fail _ _ err) = Left $ DecodeError err

runSGetWithLeftovers :: SGet a -> ByteString -> Either DNSError ((a, PState), ByteString)
runSGetWithLeftovers = runSGetWithLeftoversAt dnsTimeMid

runSPut :: SPut -> ByteString
runSPut = LBS.toStrict . BB.toLazyByteString . flip ST.evalState initialWState
