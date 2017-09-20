{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE CPP, OverloadedStrings #-}

-- | DNS Resolver and generic (lower-level) lookup functions.
module Network.DNS.Resolver (
  -- * Documentation
  -- ** Configuration for resolver
    FileOrNumericHost(..), ResolvConf(..), defaultResolvConf
  -- ** Intermediate data type for resolver
  , ResolvSeed, makeResolvSeed
  -- ** Type and function for resolver
  , Resolver(..), withResolver, withResolvers
  -- ** Looking up functions
  , lookup
  , lookupAuth
  -- ** Raw looking up function
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

import Control.Exception (bracket, throwIO)
import Control.Monad (forM)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.Maybe (fromMaybe)
import Data.Word (Word16)
import Network.BSD (getProtocolNumber)
import Network.DNS.Decode
import qualified Data.List.NonEmpty as NE
import Data.List.NonEmpty (NonEmpty(..))
import Network.DNS.Encode
import Network.DNS.Types
import Network.Socket (AddrInfoFlag(..), AddrInfo(..), SockAddr(..), Family(AF_INET, AF_INET6), PortNumber(..), HostName, Socket, SocketType(Stream, Datagram), close, socket, connect, getPeerName, getAddrInfo, defaultHints, defaultProtocol)
import Prelude hiding (lookup)
import System.IO.Error (annotateIOError, tryIOError)
import System.Random (getStdRandom, random)
import System.Timeout (timeout)
#ifdef GHC708
import Control.Applicative ((<$>), (<*>), pure)
#endif

#if defined(WIN) && defined(GHC708)
import Network.Socket (send)
import qualified Data.ByteString.Char8 as BS
import Control.Monad (when)
#else
import Network.Socket.ByteString (sendAll)
#endif

#if defined(WIN)
import Foreign.Storable (Storable(..))
import qualified Data.Text as T
import Network.DNS.Windows
#else
import Data.Char (isSpace)
import Data.List (isPrefixOf)
#endif

----------------------------------------------------------------


-- | Union type for 'FilePath' and 'HostName'. Specify 'FilePath' to
--   \"resolv.conf\" or numeric IP address in 'String' form.
--
--   /Warning/: Only numeric IP addresses are valid @RCHostName@s.
--
--   Example (using Google's public DNS cache):
--
--   >>> let cache = RCHostName "8.8.8.8"
--
data FileOrNumericHost = RCFilePath FilePath -- ^ A path for \"resolv.conf\"
                                             -- on Unix.
                                             -- A default DNS server is
                                             -- automatically detected
                                             -- on Windows.
                       | RCHostName HostName -- ^ A numeric IP address
                       | RCHostPort HostName PortNumber -- ^ A numeric IP address and port number

-- | Type for resolver configuration. The easiest way to construct a
--   @ResolvConf@ object is to modify the 'defaultResolvConf'.
data ResolvConf = ResolvConf {
    resolvInfo :: FileOrNumericHost
   -- | Timeout in micro seconds.
  , resolvTimeout :: Int
   -- | The number of retries including the first try.
  , resolvRetry :: Int
   -- | This field was obsoleted.
  , resolvBufsize :: Integer
}


-- | Return a default 'ResolvConf':
--
--     * 'resolvInfo' is 'RCFilePath' \"\/etc\/resolv.conf\".
--
--     * 'resolvTimeout' is 3,000,000 micro seconds.
--
--     * 'resolvRetry' is 3.
--
--     * 'resolvBufsize' is 512. (obsoleted)
--
--  Example (use Google's public DNS cache instead of resolv.conf):
--
--   >>> let cache = RCHostName "8.8.8.8"
--   >>> let rc = defaultResolvConf { resolvInfo = cache }
--
defaultResolvConf :: ResolvConf
defaultResolvConf = ResolvConf {
    resolvInfo = RCFilePath "/etc/resolv.conf"
  , resolvTimeout = 3 * 1000 * 1000
  , resolvRetry = 3
  , resolvBufsize = 512
}

----------------------------------------------------------------

-- | Abstract data type of DNS Resolver seed.
--   When implementing a DNS cache, this should be re-used.
data ResolvSeed = ResolvSeed {
    nameservers :: NonEmpty AddrInfo
  , rsTimeout   :: Int
  , rsRetry     :: Int
  , rsBufsize   :: Integer
}

-- | Abstract data type of DNS Resolver
--   When implementing a DNS cache, this MUST NOT be re-used.
data Resolver = Resolver {
    genId      :: IO Word16
  , dnsSocks   :: NonEmpty Socket
  , dnsTimeout :: Int
  , dnsRetry   :: Int
  , dnsBufsize :: Integer
}

----------------------------------------------------------------


-- |  Make a 'ResolvSeed' from a 'ResolvConf'.
--
--    Examples:
--
--    >>> rs <- makeResolvSeed defaultResolvConf
--
makeResolvSeed :: ResolvConf -> IO ResolvSeed
makeResolvSeed conf = do
  let tm      = resolvTimeout conf
  let retry   = resolvRetry conf
  let bufSize = resolvBufsize conf
  nameservers <- findAddresses
  return $ ResolvSeed nameservers tm retry bufSize
  where
    findAddresses :: IO (NonEmpty AddrInfo)
    findAddresses = case resolvInfo conf of
        RCHostName numhost       -> (:| []) <$> makeAddrInfo numhost Nothing
        RCHostPort numhost mport -> (:| []) <$> makeAddrInfo numhost (Just mport)
        RCFilePath file -> do
            nss <- getDefaultDnsServers file
            case nss of
              []     -> throwIO BadConfiguration
              (l:ls) -> (:|) <$> makeAddrInfo l Nothing <*> forM ls (flip makeAddrInfo Nothing)

getDefaultDnsServers :: FilePath -> IO [String]
#if defined(WIN)
getDefaultDnsServers _ = do
  res <- peek =<< getWindowsDefDnsServers
  case dnsError res of
    0 -> return $ map T.unpack (T.splitOn "," (T.pack (dnsAddresses res)))
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
    let hints = defaultHints {
            addrFlags = [AI_ADDRCONFIG, AI_NUMERICHOST, AI_PASSIVE]
          , addrSocketType = Datagram
          , addrProtocol = proto
          }
    a:_ <- getAddrInfo (Just hints) (Just addr) (Just "domain")
    let connectPort = case addrAddress a of
                        SockAddrInet pn ha -> SockAddrInet (fromMaybe pn mport) ha
                        SockAddrInet6 pn fi ha sid -> SockAddrInet6 (fromMaybe pn mport) fi ha sid
                        unixAddr -> unixAddr
    return $ a { addrAddress = connectPort }

----------------------------------------------------------------


-- | Giving a thread-safe 'Resolver' to the function of the second
--   argument. A socket for UDP is opened inside and is surely closed.
--   Multiple 'withResolver's can be used concurrently.
--   Multiple lookups must be done sequentially with a given
--   'Resolver'. If multiple 'Resolver's are necessary for
--   concurrent purpose, use 'withResolvers'.
withResolver :: ResolvSeed -> (Resolver -> IO a) -> IO a
withResolver seed f = bracket (initSockets seed) (mapM_ close) (f . makeResolver seed)

-- | Giving thread-safe 'Resolver's to the function of the second
--   argument. Sockets for UDP are opened inside and are surely closed.
--   For each 'Resolver', multiple lookups must be done sequentially.
--   'Resolver's can be used concurrently.
withResolvers :: [ResolvSeed] -> ([Resolver] -> IO a) -> IO a
withResolvers seeds func = bracket (mapM initSockets seeds) closeSockets $ \socks -> do
    let resolvs = zipWith makeResolver seeds socks
    func resolvs
  where
    closeSockets = mapM_ close . concatMap NE.toList

-- | Atomically create and connect to all the nameservers listed in the given
-- `ResolvSeed`.
initSockets :: ResolvSeed -> IO (NonEmpty Socket)
initSockets seed = mapM initSocket addrs
  where
    initSocket ai = do sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
                       connect sock (addrAddress ai)
                       return sock
    addrs         = nameservers seed

makeResolver :: ResolvSeed -> NonEmpty Socket -> Resolver
makeResolver seed socks = Resolver {
    genId = getRandom
  , dnsSocks = socks
  , dnsTimeout = rsTimeout seed
  , dnsRetry = rsRetry seed
  , dnsBufsize = rsBufsize seed
  }

getRandom :: IO Word16
getRandom = getStdRandom random

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
    _         -> Left UnknownError
  where
    errcode = rcode . flags . header

-- | For backward compatibility.
fromDNSFormat :: DNSMessage -> (DNSMessage -> a) -> Either DNSError a
fromDNSFormat = fromDNSMessage

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


-- | Look up a name and return the entire DNS Response.  If the
--   initial UDP query elicits a truncated answer, the query is
--   retried over TCP.  The TCP retry may extend the total time
--   taken by one more timeout beyond timeout * tries.
--
--   Sample output is included below, however it is /not/ tested
--   the sequence number is unpredictable (it has to be!).
--
--   The example code:
--
--   @
--   let hostname = Data.ByteString.Char8.pack \"www.example.com\"
--   rs <- makeResolvSeed defaultResolvConf
--   withResolver rs $ \resolver -> lookupRaw resolver hostname A
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
lookupRaw = lookupRawInternal receive False

-- | Same as lookupRaw, but the query sets the AD bit, which solicits the
--   the authentication status in the server reply.  In most applications
--   (other than diagnostic tools) that want authenticated data It is
--   unwise to trust the AD bit in the responses of non-local servers, this
--   interface should in most cases only be used with a loopback resolver.
--
lookupRawAD :: Resolver -> Domain -> TYPE -> IO (Either DNSError DNSMessage)
lookupRawAD = lookupRawInternal receive True

-- Lookup loop, we try UDP until we get a response.  If the response
-- is truncated, we try TCP once, with no further UDP retries.
-- EDNS0 support would significantly reduce the need for TCP retries.
--
-- For now, we optimize for low latency high-availability caches
-- (e.g.  running on a loopback interface), where TCP is cheap
-- enough.  We could attempt to complete the TCP lookup within the
-- original time budget of the truncated UDP query, by wrapping both
-- within a a single 'timeout' thereby staying within the original
-- time budget, but it seems saner to give TCP a full opportunity to
-- return results.  TCP latency after a truncated UDP reply will be
-- atypical.
--
-- Future improvements might also include support for TCP on the
-- initial query.

lookupRawInternal ::
    (Socket -> IO DNSMessage)
    -> Bool
    -> Resolver
    -> Domain
    -> TYPE
    -> IO (Either DNSError DNSMessage)
lookupRawInternal _ _ _   dom _
  | isIllegal dom     = return $ Left IllegalDomain
lookupRawInternal rcv ad rlv dom typ = loop (NE.uncons (dnsSocks rlv))
  where
    loop :: (Socket, Maybe (NonEmpty Socket)) -> IO (Either DNSError DNSMessage)
    loop (sock, alternatives) = do
      res <- initialise >>= \(query, checkSeqno) ->
        performLookup sock query checkSeqno 0 False
      case res of
        Left e  -> maybe (return (Left e)) (loop . NE.uncons) alternatives
        Right v -> pure (Right v)

    initialise = do
      seqno <- genId rlv
      let query = (if ad then composeQueryAD else composeQuery) seqno [q]
      let checkSeqno = check seqno
      return (query, checkSeqno)

    performLookup sock query checkSeqno cnt mismatch
      | cnt == retry = do
          let ret | mismatch  = SequenceNumberMismatch
                  | otherwise = RetryLimitExceeded
          return $ Left ret
      | otherwise    = do
          -- We don't expect to block or raise exceptions when writing UDP.
          -- Reads, can time out, or, since we connect the UDP socket, throw
          -- connection refused.  Regardless, we simply handle timeouts and
          -- exceptions for the combined write request + read reply operation.
          -- IO exceptions are annotated with the protocol and address.
          response <- timeout tm (tryIOError (sendAll sock query >> rcv sock))
          case response of
              Nothing  -> performLookup sock query checkSeqno (cnt + 1) False
              Just (Right res) -> do
                  let valid = checkSeqno res
                  case valid of
                      False  -> performLookup sock query checkSeqno (cnt + 1) False
                      True | not $ trunCation $ flags $ header res
                             -> return $ Right res
                      _      -> tcpRetry query sock tm
              Just (Left e) -> do
                  peer <- getPeerName sock
                  return $ Left $ NetworkFailure $
                      annotateIOError e (show peer) Nothing $ Just "UDP"
    tm = dnsTimeout rlv
    retry = dnsRetry rlv
    q = Question dom typ
    check seqno res = identifier (header res) == seqno

-- Create a TCP socket `just like` our UDP socket and retry the same
-- query over TCP.  Since TCP is a reliable transport, and we just
-- got a (truncated) reply from the server over UDP (so it has the
-- answer, but it is just too large for UDP), we expect to succeed
-- quickly on the first try.  There will be no further retries.

tcpRetry :: ByteString
         -> Socket
         -> Int
         -> IO (Either DNSError DNSMessage)
tcpRetry query sock tm = do
    peer <- getPeerName sock
    bracket (tcpOpen peer)
            (maybe (return ()) close)
            (tcpLookup query peer tm)

-- Create a TCP socket with the given socket address (taken from a
-- corresponding UDP socket).  This might throw an I/O Exception
-- if we run out of file descriptors.  Should this use tryIOError,
-- and return "Nothing" also in that case?  If so, perhaps similar
-- code is needed in openSocket, but that has to wait until we
-- refactor `withResolver` to not do "early" socket allocation, and
-- instead allocate a fresh UDP socket for each `lookupRawInternal`
-- invocation.  It would be bad to fail an entire `withResolver`
-- action, if the socket shortage is transient, and the user intends
-- to make many DNS queries with the same resolver handle.

tcpOpen :: SockAddr -> IO (Maybe Socket)
tcpOpen peer = case peer of
    SockAddrInet{}  -> Just <$> socket AF_INET  Stream defaultProtocol
    SockAddrInet6{} -> Just <$> socket AF_INET6 Stream defaultProtocol
    _ -> return Nothing -- Only IPv4 and IPv6 are possible

-- Perform a DNS query over TCP, if we were successful in creating
-- the TCP socket.  The socket creation can only fail if we run out
-- of file descriptors, we're not making connections here.  Failure
-- is reported as "server" failure, though it is really our stub
-- resolver that's failing.  This is likely good enough.

tcpLookup :: ByteString
          -> SockAddr
          -> Int
          -> Maybe Socket
          -> IO (Either DNSError DNSMessage)
tcpLookup _ _ _ Nothing = return $ Left ServerFailure
tcpLookup query peer tm (Just vc) = do
    -- With TCP, we can get fail or time out with any of connect, send
    -- or receive.
    response <- timeout tm $ tryIOError $ do
        connect vc peer
        sendAll vc $ encodeVC query
        receiveVC vc
    case response of
        Nothing  -> return $ Left TimeoutExpired
        Just (Right res) -> return $ Right res
        Just (Left e)    -> return $ Left $ NetworkFailure $
            annotateIOError e (show peer) Nothing $ Just "TCP"

#if defined(WIN) && defined(GHC708)
-- Windows does not support sendAll in Network.ByteString for older GHCs.
sendAll :: Socket -> BS.ByteString -> IO ()
sendAll sock bs = do
  sent <- send sock (BS.unpack bs)
  when (sent < fromIntegral (BS.length bs)) $ sendAll sock (BS.drop (fromIntegral sent) bs)
#endif

badLength :: Domain -> Bool
badLength dom
    | BS.null dom        = True
    | BS.last dom == '.' = BS.length dom > 254
    | otherwise          = BS.length dom > 253

isIllegal :: Domain -> Bool
isIllegal dom
  | badLength dom               = True
  | '.' `BS.notElem` dom        = True
  | ':' `BS.elem` dom           = True
  | '/' `BS.elem` dom           = True
  | any (\x -> BS.length x > 63)
        (BS.split '.' dom)      = True
  | otherwise                   = False
