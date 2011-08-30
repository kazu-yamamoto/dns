module Network.DNS.StateBinary where

import Blaze.ByteString.Builder
import Control.Monad.State
import Data.Binary.Get
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import Data.Int
import Data.IntMap (IntMap)
import qualified Data.IntMap as IM (insert, lookup, empty)
import Data.Word
import Network.DNS.Types
import Prelude hiding (lookup)

----------------------------------------------------------------

type SGet = StateT PState Get

type PState = IntMap Domain

----------------------------------------------------------------

(<$>) :: (Monad m) => (a -> b) -> m a -> m b
(<$>) = liftM

(<$) :: (Monad m) => b -> m a -> m b
x <$ y = y >> return x

(<*>) :: (Monad m) => m (a -> b) -> m a -> m b
(<*>) = ap

(<*) :: (Monad m) => m a -> m b -> m a
(<*) ma mb = do
    a <- ma
    mb
    return a

----------------------------------------------------------------

type SPut = Write

put8 :: Word8 -> SPut
put8  = writeWord8

put16 :: Word16 -> SPut
put16 = writeWord16be

put32 :: Word32 -> SPut
put32 = writeWord32be

putInt8 :: Int8 -> SPut
putInt8  = writeInt8

putInt16 :: Int16 -> SPut
putInt16 = writeInt16be

putInt32 :: Int32 -> SPut
putInt32 = writeInt32be

----------------------------------------------------------------

get8 :: SGet Word8
get8  = lift getWord8

get16 :: SGet Word16
get16 = lift getWord16be

get32 :: SGet Word32
get32 = lift getWord32be

getInt8 :: SGet Int
getInt8 = fromIntegral <$> get8

getInt16 :: SGet Int
getInt16 = fromIntegral <$> get16

getInt32 :: SGet Int
getInt32 = fromIntegral <$> get32

----------------------------------------------------------------

getPosition :: SGet Int
getPosition = fromIntegral <$> lift bytesRead

getNBytes :: Int -> SGet [Int]
getNBytes len = toInts <$> getNByteString len
  where
    toInts = map ord . BS.unpack

getNByteString :: Int -> SGet ByteString
getNByteString = lift . getByteString . fromIntegral

----------------------------------------------------------------

push :: Int -> Domain -> SGet ()
push n d = modify (IM.insert n d)

pop :: Int -> SGet (Maybe Domain)
pop n = IM.lookup n <$> get

----------------------------------------------------------------

initialState :: IntMap Domain
initialState = IM.empty

runSGet :: SGet DNSFormat -> L.ByteString -> DNSFormat
runSGet res bs = fst $ runGet (runStateT res initialState) bs

runSPut :: SPut -> L.ByteString
runSPut = toLazyByteString . fromWrite
