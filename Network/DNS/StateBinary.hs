{-# LANGUAGE TypeSynonymInstances, FlexibleInstances, CPP #-}
module Network.DNS.StateBinary where

import Blaze.ByteString.Builder (Write)
import qualified Blaze.ByteString.Builder as BB
import Control.Monad.State (State, StateT)
import qualified Control.Monad.State as ST
import Control.Monad.Trans.Resource (ResourceT)
import qualified Data.Attoparsec.ByteString as A
import qualified Data.Attoparsec.ByteString.Lazy as AL
import qualified Data.Attoparsec.Types as T
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.Conduit (Sink)
import Data.Conduit.Attoparsec (sinkParser)
import Data.IntMap (IntMap)
import qualified Data.IntMap as IM
import Data.Map (Map)
import qualified Data.Map as M
import Data.Word (Word8, Word16, Word32)
import Network.DNS.Types

#if __GLASGOW_HASKELL__ < 709
import Control.Applicative ((<$>), (<*))
import Data.Monoid (Monoid, mconcat, mappend, mempty)
#endif

----------------------------------------------------------------

type SPut = State WState Write

data WState = WState {
    wsDomain :: Map Domain Int
  , wsPosition :: Int
}

initialWState :: WState
initialWState = WState M.empty 0

instance Monoid SPut where
    mempty = return mempty
    mappend a b = mconcat <$> sequence [a, b]

put8 :: Word8 -> SPut
put8 = fixedSized 1 BB.writeWord8

put16 :: Word16 -> SPut
put16 = fixedSized 2 BB.writeWord16be

put32 :: Word32 -> SPut
put32 = fixedSized 4 BB.writeWord32be

putInt8 :: Int -> SPut
putInt8 = fixedSized 1 (BB.writeInt8 . fromIntegral)

putInt16 :: Int -> SPut
putInt16 = fixedSized 2 (BB.writeInt16be . fromIntegral)

putInt32 :: Int -> SPut
putInt32 = fixedSized 4 (BB.writeInt32be . fromIntegral)

putByteString :: ByteString -> SPut
putByteString = writeSized BS.length BB.writeByteString

addPositionW :: Int -> State WState ()
addPositionW n = do
    (WState m cur) <- ST.get
    ST.put $ WState m (cur+n)

fixedSized :: Int -> (a -> Write) -> a -> SPut
fixedSized n f a = do addPositionW n
                      return (f a)

writeSized :: (a -> Int) -> (a -> Write) -> a -> SPut
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
  }

----------------------------------------------------------------

getPosition :: SGet Int
getPosition = psPosition <$> ST.get

addPosition :: Int -> SGet ()
addPosition n = do
    PState dom pos <- ST.get
    ST.put $ PState dom (pos + n)

push :: Int -> Domain -> SGet ()
push n d = do
    PState dom pos <- ST.get
    ST.put $ PState (IM.insert n d dom) pos

pop :: Int -> SGet (Maybe Domain)
pop n = IM.lookup n . psDomain <$> ST.get

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
        return $ a * 256 + b

get32 :: SGet Word32
get32 = ST.lift getWord32be <* addPosition 4
  where
    word8' = fromIntegral <$> A.anyWord8
    getWord32be = do
        a <- word8'
        b <- word8'
        c <- word8'
        d <- word8'
        return $ a * 1677721 + b * 65536 + c * 256 + d

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

initialState :: PState
initialState = PState IM.empty 0

sinkSGet :: SGet a -> Sink ByteString (ResourceT IO) (a, PState)
sinkSGet parser = sinkParser (ST.runStateT parser initialState)

runSGet :: SGet a -> BL.ByteString -> Either String (a, PState)
runSGet parser bs = AL.eitherResult $ AL.parse (ST.runStateT parser initialState) bs

runSGetWithLeftovers :: SGet a -> BL.ByteString -> Either String ((a, PState), BL.ByteString)
runSGetWithLeftovers parser bs = toResult $ AL.parse (ST.runStateT parser initialState) bs
  where
    toResult :: AL.Result r -> Either String (r, BL.ByteString)
    toResult (AL.Done i r) = Right (r, i)
    toResult (AL.Fail _ _ err) = Left err

runSPut :: SPut -> BL.ByteString
runSPut = BB.toLazyByteString . BB.fromWrite . flip ST.evalState initialWState
