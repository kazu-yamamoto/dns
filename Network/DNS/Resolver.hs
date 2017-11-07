{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}

-- | DNS Resolver and generic (lower-level) lookup functions.
module Network.DNS.Resolver (
  -- * Configuration for resolver
    ResolvConf
  , defaultResolvConf
  -- ** Accessors
  , resolvInfo
  , resolvTimeout
  , resolvRetry
  , resolvEDNS
  -- ** Related types
  , FileOrNumericHost(..)
  -- * Intermediate data type for resolver
  , ResolvSeed
  , makeResolvSeed
  -- * Type and function for resolver
  , Resolver
  , withResolver
  , withResolvers
  -- * Looking up functions
  , lookup
  , lookupAuth
  -- * Raw looking up function
  , lookupRaw
  , lookupRawAD
  , fromDNSMessage
  , fromDNSFormat
  ) where

#if !defined(mingw32_HOST_OS)
#define POSIX
#else
#define WIN
#endif

#if __GLASGOW_HASKELL__ < 709
#define GHC708
#endif

import qualified Data.ByteString as BS
import Control.Exception as E
import Control.Monad (forM)
import Data.Maybe (isJust, maybe)
import qualified Crypto.Random as C
import Data.IORef (IORef)
import qualified Data.IORef as I
import Data.List.NonEmpty (NonEmpty(..))
import Data.Word (Word16)
import Network.BSD (getProtocolNumber)
import Network.DNS.IO
import Network.DNS.Transport
import Network.DNS.Types
import Network.DNS.Types.Internal
import Network.Socket (AddrInfoFlag(..), AddrInfo(..), PortNumber(..), HostName, SocketType(Datagram), getAddrInfo, defaultHints)
import Prelude hiding (lookup)

#ifdef GHC708
import Control.Applicative ((<$>), (<*>), pure)
#endif

#if defined(WIN)
import qualified Data.List.Split as Split
import Foreign.C.String
import Foreign.Marshal.Alloc (allocaBytes)
import Data.Word
#else
import Data.Char (isSpace)
import Data.List (isPrefixOf)
#endif

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

getDefaultDnsServers :: FilePath -> IO [String]
#if defined(WIN)
foreign import ccall "getWindowsDefDnsServers" getWindowsDefDnsServers :: CString -> Int -> IO Word32
getDefaultDnsServers _ = do
  allocaBytes 128 $ \cString -> do
     res <- getWindowsDefDnsServers cString 128
     case res of
       0 -> do
         addresses <- peekCString cString
         return $ filter (not . null) . Split.splitOn "," $ addresses
       _ -> do
         -- TODO: Do proper error handling here.
         return mempty
#else
getDefaultDnsServers file = toAddresses <$> readFile file
  where
    toAddresses :: String -> [String]
    toAddresses cs = map extract (filter ("nameserver" `isPrefixOf`) (lines cs))
    extract = reverse . dropWhile isSpace . reverse . dropWhile isSpace . drop 11
#endif

makeAddrInfo :: HostName -> Maybe PortNumber -> IO AddrInfo
makeAddrInfo addr mport = do
    proto <- getProtocolNumber "udp"
    let flags = [AI_ADDRCONFIG, AI_NUMERICHOST, AI_PASSIVE]
        hints = defaultHints {
            addrFlags = if isJust mport then AI_NUMERICSERV : flags else flags
          , addrSocketType = Datagram
          , addrProtocol = proto
          }
        serv = maybe "domain" show mport
    head <$> getAddrInfo (Just hints) (Just addr) (Just serv)

----------------------------------------------------------------

-- | Giving a thread-safe 'Resolver' to the function of the second
--   argument.  Multiple 'withResolver's can be used concurrently.
--   Multiple lookups must be done sequentially with a given
--   'Resolver'. If multiple 'Resolver's are needed concurrently,
--   use 'withResolvers'.
withResolver :: ResolvSeed -> (Resolver -> IO a) -> IO a
withResolver seed f = makeResolver seed >>= f

-- | Giving thread-safe 'Resolver's to the function of the second
--   argument.  For each 'Resolver', multiple lookups must be done
--   sequentially.  'Resolver's can be used concurrently.
withResolvers :: [ResolvSeed] -> ([Resolver] -> IO a) -> IO a
withResolvers seeds f = mapM makeResolver seeds >>= f

makeResolver :: ResolvSeed -> IO Resolver
makeResolver seed = do
  ref <- C.drgNew >>= I.newIORef
  return $ Resolver seed (getRandom ref)

getRandom :: IORef C.ChaChaDRG -> IO Word16
getRandom ref = I.atomicModifyIORef' ref $ \gen ->
  let (bs, gen') = C.randomBytesGenerate 2 gen
      [u,l] = map fromIntegral $ BS.unpack bs
      !seqno = u * 256 + l
  in (gen', seqno)

----------------------------------------------------------------

-- | Looking up resource records of a domain. The first parameter is one of
--   the field accessors of the 'DNSMessage' type -- this allows you to
--   choose which section (answer, authority, or additional) you would like
--   to inspect for the result.

lookupSection :: (DNSMessage -> [ResourceRecord])
              -> Resolver
              -> Domain
              -> TYPE
              -> IO (Either DNSError [RData])
lookupSection section rlv dom typ = do
    eans <- lookupRaw rlv dom typ
    case eans of
        Left  err -> return $ Left err
        Right ans -> return $ fromDNSMessage ans toRData
  where
    {- CNAME hack
    dom' = if "." `isSuffixOf` dom then dom else dom ++ "."
    correct r = rrname r == dom' && rrtype r == typ
    -}
    correct ResourceRecord{..} = rrtype == typ
    toRData x = map rdata . filter correct $ section x

-- | Extract necessary information from 'DNSMessage'
fromDNSMessage :: DNSMessage -> (DNSMessage -> a) -> Either DNSError a
fromDNSMessage ans conv = case errcode ans of
    NoErr     -> Right $ conv ans
    FormatErr -> Left FormatError
    ServFail  -> Left ServerFailure
    NameErr   -> Left NameError
    NotImpl   -> Left NotImplemented
    Refused   -> Left OperationRefused
    BadOpt    -> Left BadOptRecord
    _         -> Left UnknownDNSError
  where
    errcode = rcode . flags . header

{-# DEPRECATED fromDNSFormat "Use fromDNSMessage instead" #-}
-- | For backward compatibility.
fromDNSFormat :: DNSMessage -> (DNSMessage -> a) -> Either DNSError a
fromDNSFormat = fromDNSMessage

----------------------------------------------------------------

-- | Look up resource records for a domain, collecting the results
--   from the ANSWER section of the response.
--
--   We repeat an example from "Network.DNS.Lookup":
--
--   >>> let hostname = Data.ByteString.Char8.pack "www.example.com"
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookup resolver hostname A
--   Right [93.184.216.34]
--
lookup :: Resolver -> Domain -> TYPE -> IO (Either DNSError [RData])
lookup = lookupSection answer

-- | Look up resource records for a domain, collecting the results
--   from the AUTHORITY section of the response.
lookupAuth :: Resolver -> Domain -> TYPE -> IO (Either DNSError [RData])
lookupAuth = lookupSection authority

----------------------------------------------------------------

-- | Look up a name and return the entire DNS Response
--
--  For each IP address of the DNS server:
--
--  * Try UDP queries with the limitation of 'resolvRetry'.
--  * If the response is truncated, try a TCP query only once.
--
--   The example code:
--
--   @
--   let hostname = Data.ByteString.Char8.pack \"www.example.com\"
--   rs <- makeResolvSeed defaultResolvConf
--   withResolver rs $ \\resolver -> lookupRaw resolver hostname A
--   @
--
--   And the (formatted) expected output:
--
--   @
--   Right (DNSMessage
--           { header = DNSHeader
--                        { identifier = 1,
--                          flags = DNSFlags
--                                    { qOrR = QR_Response,
--                                      opcode = OP_STD,
--                                      authAnswer = False,
--                                      trunCation = False,
--                                      recDesired = True,
--                                      recAvailable = True,
--                                      rcode = NoErr,
--                                      authenData = False
--                                    },
--                        },
--             question = [Question { qname = \"www.example.com.\",
--                                    qtype = A}],
--             answer = [ResourceRecord {rrname = \"www.example.com.\",
--                                       rrtype = A,
--                                       rrttl = 800,
--                                       rdlen = 4,
--                                       rdata = 93.184.216.119}],
--             authority = [],
--             additional = []})
--  @
--
lookupRaw :: Resolver -> Domain -> TYPE -> IO (Either DNSError DNSMessage)
lookupRaw = resolve receive False

-- | Same as lookupRaw, but the query sets the AD bit, which solicits the
--   the authentication status in the server reply.  In most applications
--   (other than diagnostic tools) that want authenticated data It is
--   unwise to trust the AD bit in the responses of non-local servers, this
--   interface should in most cases only be used with a loopback resolver.
--
lookupRawAD :: Resolver -> Domain -> TYPE -> IO (Either DNSError DNSMessage)
lookupRawAD = resolve receive True
