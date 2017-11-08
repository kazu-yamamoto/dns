module Network.DNS.Memo where

import Control.Applicative ((<$>))
import Data.ByteString.Short (ShortByteString)
import Data.IORef (IORef, newIORef, readIORef, atomicModifyIORef', IORef)
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as PSQ
import Data.Time (UTCTime)

import Network.DNS.Types

type Key = (ShortByteString -- avoiding memory fragmentation
           ,TYPE)
type Prio = UTCTime

type Entry = Either DNSError [RData]

type PSQ = OrdPSQ
newtype CacheRef = CacheRef (IORef (PSQ Key Prio Entry))

newCacheRef :: IO CacheRef
newCacheRef = CacheRef <$> newIORef PSQ.empty

lookupCacheRef :: Key -> CacheRef -> IO (Maybe (Prio, Entry))
lookupCacheRef key (CacheRef ref) = PSQ.lookup key <$> readIORef ref

insertCacheRef :: Key -> Prio -> Entry -> CacheRef -> IO ()
insertCacheRef key tim ent (CacheRef ref) =
    atomicModifyIORef' ref $ \q -> (PSQ.insert key tim ent q, ())

pruneCacheRef :: Prio -> CacheRef -> IO ()
pruneCacheRef tim (CacheRef ref) =
    atomicModifyIORef' ref $ \p -> (snd (PSQ.atMostView tim p), ())
