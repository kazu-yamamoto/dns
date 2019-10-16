{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}

-- | Resolver related data types.
module Network.DNS.Resolver (
  -- * Configuration for resolver
    ResolvConf
  , defaultResolvConf
  -- ** Accessors
  , resolvInfo
  , resolvTimeout
  , resolvRetry
  , resolvConcurrent
  , resolvCache
  , resolvQueryControls
  -- ** Specifying DNS servers
  , FileOrNumericHost(..)
  -- ** Configuring cache
  , CacheConf
  , defaultCacheConf
  , maximumTTL
  , pruningDelay
  -- * Intermediate data type for resolver
  , ResolvSeed
  , makeResolvSeed
  -- * Type and function for resolver
  , Resolver
  , withResolver
  , withResolvers
  ) where

import Control.Exception as E
import qualified Crypto.Random as C
import qualified Data.ByteString as BS
import Data.IORef (IORef)
import qualified Data.IORef as I
import qualified Data.List.NonEmpty as NE
import Network.Socket (AddrInfoFlag(..), AddrInfo(..), PortNumber, HostName, SocketType(Datagram), getAddrInfo, defaultHints)
import Prelude

import Network.DNS.Imports
import Network.DNS.Memo
import Network.DNS.Transport
import Network.DNS.Types.Internal
import Network.DNS.Types.Resolver
import Network.DNS.Resolver.Internal

----------------------------------------------------------------

-- |  Make a 'ResolvSeed' from a 'ResolvConf'.
--
--    Examples:
--
--    >>> rs <- makeResolvSeed defaultResolvConf
--
makeResolvSeed :: ResolvConf -> IO ResolvSeed
makeResolvSeed conf = ResolvSeed conf <$> findAddresses
  where
    findAddresses :: IO (NonEmpty AddrInfo)
    findAddresses = case resolvInfo conf of
        RCHostName numhost       -> (:| []) <$> makeAddrInfo numhost Nothing
        RCHostPort numhost mport -> (:| []) <$> makeAddrInfo numhost (Just mport)
        RCHostNames nss          -> mkAddrs nss
        RCFilePath file          -> getDefaultDnsServers file >>= mkAddrs
    mkAddrs []     = E.throwIO BadConfiguration
    mkAddrs (l:ls) = (:|) <$> makeAddrInfo l Nothing <*> forM ls (`makeAddrInfo` Nothing)

makeAddrInfo :: HostName -> Maybe PortNumber -> IO AddrInfo
makeAddrInfo addr mport = do
    let flgs = [AI_ADDRCONFIG, AI_NUMERICHOST, AI_PASSIVE]
        hints = defaultHints {
            addrFlags = if isJust mport then AI_NUMERICSERV : flgs else flgs
          , addrSocketType = Datagram
          }
        serv = maybe "domain" show mport
    head <$> getAddrInfo (Just hints) (Just addr) (Just serv)

----------------------------------------------------------------

-- | Giving a thread-safe 'Resolver' to the function of the second
--   argument.
withResolver :: ResolvSeed -> (Resolver -> IO a) -> IO a
withResolver seed f = makeResolver seed >>= f

{-# DEPRECATED withResolvers "Use withResolver with resolvConcurrent set to True" #-}
-- | Giving thread-safe 'Resolver's to the function of the second
--   argument.  For each 'Resolver', multiple lookups must be done
--   sequentially.  'Resolver's can be used concurrently.
withResolvers :: [ResolvSeed] -> ([Resolver] -> IO a) -> IO a
withResolvers seeds f = mapM makeResolver seeds >>= f

makeResolver :: ResolvSeed -> IO Resolver
makeResolver seed = do
  let n = NE.length $ nameservers seed
  refs <- replicateM n (C.drgNew >>= I.newIORef)
  let gens = NE.fromList $ map getRandom refs
  case resolvCache $ resolvconf seed of
    Just cacheconf -> do
        c <- newCache $ pruningDelay cacheconf
        return $ Resolver seed gens $ Just c
    Nothing -> return $ Resolver seed gens Nothing

getRandom :: IORef C.ChaChaDRG -> IO Word16
getRandom ref = I.atomicModifyIORef' ref $ \gen ->
  let (bs, gen') = C.randomBytesGenerate 2 gen
      [u,l] = map fromIntegral $ BS.unpack bs
      !seqno = u * 256 + l
  in (gen', seqno)
