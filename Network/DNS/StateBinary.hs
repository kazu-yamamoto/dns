module Network.DNS.StateBinary where

import Blaze.ByteString.Builder
import Control.Applicative
import Control.Monad.State
import Data.Attoparsec
import Data.Attoparsec.Enumerator
import qualified Data.Attoparsec.Lazy as AL
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS (unpack)
import qualified Data.ByteString.Lazy as BL (ByteString)
import Data.Enumerator (Iteratee)
import Data.Int
import Data.IntMap (IntMap)
import qualified Data.IntMap as IM (insert, lookup, empty)
import Data.Word
import Network.DNS.Types
import Prelude hiding (lookup, take)

----------------------------------------------------------------

type SPut = Write

put8 :: Word8 -> SPut
put8  = writeWord8

put16 :: Word16 -> SPut
put16 = writeWord16be

put32 :: Word32 -> SPut
put32 = writeWord32be

putInt8 :: Int -> SPut
putInt8  = writeInt8 . fromIntegral

putInt16 :: Int -> SPut
putInt16 = writeInt16be . fromIntegral

putInt32 :: Int -> SPut
putInt32 = writeInt32be . fromIntegral

----------------------------------------------------------------

type SGet = StateT PState Parser

data PState = PState {
    psDomain :: IntMap Domain
  , psPosition :: Int
  }

----------------------------------------------------------------

getPosition :: SGet Int
getPosition = psPosition <$> get

addPosition :: Int -> SGet ()
addPosition n = do
    PState dom pos <- get
    put $ PState dom (pos + n)

push :: Int -> Domain -> SGet ()
push n d = do
    PState dom pos <- get
    put $ PState (IM.insert n d dom) pos

pop :: Int -> SGet (Maybe Domain)
pop n = IM.lookup n . psDomain <$> get

----------------------------------------------------------------

get8 :: SGet Word8
get8  = lift anyWord8 <* addPosition 1

get16 :: SGet Word16
get16 = lift getWord16be <* addPosition 2
  where
    word8' = fromIntegral <$> anyWord8
    getWord16be = do
        a <- word8'
        b <- word8'
        return $ a * 256 + b

get32 :: SGet Word32
get32 = lift getWord32be <* addPosition 4
  where
    word8' = fromIntegral <$> anyWord8
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
getNByteString n = lift (take n) <* addPosition n

----------------------------------------------------------------

initialState :: PState
initialState = PState IM.empty 0

iterSGet :: Monad m => SGet a -> Iteratee ByteString m (a, PState)
iterSGet parser = iterParser (runStateT parser initialState)

runSGet :: SGet a -> BL.ByteString -> Either String (a, PState)
runSGet parser bs = AL.eitherResult $ AL.parse (runStateT parser initialState) bs

runSPut :: SPut -> BL.ByteString
runSPut = toLazyByteString . fromWrite
