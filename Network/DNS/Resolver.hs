{-# LANGUAGE CPP #-}
{-|
  DNS Resolver and lookup functions.

  Sample code:

@
    import qualified Network.DNS as DNS (lookup)
    import Network.DNS hiding (lookup)
    main :: IO ()
    main = do
        rs <- makeResolvSeed defaultResolvConf
        withResolver rs $ \\resolver -> do
            DNS.lookup resolver \"www.example.com\" A >>= print
@
-}

module Network.DNS.Resolver (
  -- * Documentation
  -- ** Configuration for resolver
    FileOrNumericHost(..), ResolvConf(..), defaultResolvConf
  -- ** Intermediate data type for resolver
  , ResolvSeed, makeResolvSeed
  -- ** Type and function for resolver
  , Resolver(..), withResolver
  -- ** Looking up functions
  , lookup, lookupRaw
  ) where

import Control.Applicative
import Control.Exception
import Data.Char
import Data.Int
import Data.List hiding (find, lookup)
import Network.BSD
import Network.DNS.Decode
import Network.DNS.Encode
import Network.DNS.Internal
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString.Lazy
import Prelude hiding (lookup)
import System.Random
import System.Timeout

#if mingw32_HOST_OS == 1
import Network.Socket (send)
import qualified Data.ByteString.Lazy.Char8 as LB
import Control.Monad (when)
#endif
----------------------------------------------------------------

{-|
  Union type for 'FilePath' and 'HostName'. Specify 'FilePath' to
  \"resolv.conf\" or numeric IP address in 'String' form.
-}
data FileOrNumericHost = RCFilePath FilePath | RCHostName HostName

{-|
  Type for resolver configuration
-}
data ResolvConf = ResolvConf {
    resolvInfo :: FileOrNumericHost
  , resolvTimeout :: Int
  -- | This field was obsoleted.
  , resolvBufsize :: Integer
}

{-|
  Default 'ResolvConf'.
  'resolvInfo' is 'RCFilePath' \"\/etc\/resolv.conf\".
  'resolvTimeout' is 3,000,000 micro seconds.
  'resolvBufsize' is 512. (obsoleted)
-}
defaultResolvConf :: ResolvConf
defaultResolvConf = ResolvConf {
    resolvInfo = RCFilePath "/etc/resolv.conf"
  , resolvTimeout = 3 * 1000 * 1000
  , resolvBufsize = 512
}

----------------------------------------------------------------

{-|
  Abstract data type of DNS Resolver seed
-}
data ResolvSeed = ResolvSeed {
    addrInfo :: AddrInfo
  , rsTimeout :: Int
  , rsBufsize :: Integer
}

{-|
  Abstract data type of DNS Resolver
-}
data Resolver = Resolver {
    genId   :: IO Int
  , dnsSock :: Socket
  , dnsTimeout :: Int
  , dnsBufsize :: Integer
}

----------------------------------------------------------------

{-|
  Making 'ResolvSeed' from an IP address of a DNS cache server.
-}
makeResolvSeed :: ResolvConf -> IO ResolvSeed
makeResolvSeed conf = ResolvSeed <$> addr
                                 <*> pure (resolvTimeout conf)
                                 <*> pure (resolvBufsize conf)
  where
    addr = case resolvInfo conf of
        RCHostName numhost -> makeAddrInfo numhost
        RCFilePath file -> toAddr <$> readFile file >>= makeAddrInfo
    toAddr cs = let l:_ = filter ("nameserver" `isPrefixOf`) $ lines cs
                in extract l
    extract = reverse . dropWhile isSpace . reverse . dropWhile isSpace . drop 11

makeAddrInfo :: HostName -> IO AddrInfo
makeAddrInfo addr = do
    proto <- getProtocolNumber "udp"
    let hints = defaultHints {
            addrFlags = [AI_ADDRCONFIG, AI_NUMERICHOST, AI_PASSIVE]
          , addrSocketType = Datagram
          , addrProtocol = proto
          }
    a:_ <- getAddrInfo (Just hints) (Just addr) (Just "domain")
    return a

----------------------------------------------------------------

{-|
  Giving a thread-safe 'Resolver' to the function of the second
  argument. 'withResolver' should be passed to 'forkIO'.
-}

withResolver :: ResolvSeed -> (Resolver -> IO a) -> IO a
withResolver seed func = do
  let ai = addrInfo seed
  sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
  connect sock (addrAddress ai)
  let resolv = Resolver {
          genId = getRandom
        , dnsSock = sock
        , dnsTimeout = rsTimeout seed
        , dnsBufsize = rsBufsize seed
        }
  func resolv `finally` sClose sock

getRandom :: IO Int
getRandom = getStdRandom (randomR (0,65535))

----------------------------------------------------------------

{-|
  Looking up resource records of a domain. The first parameter is one of
  the field accessors of the 'DNSFormat' type -- this allows you to
  choose which section (answer, authority, or additional) you would like
  to inspect for the result.
-}
lookupSection :: (DNSFormat -> [ResourceRecord])
              -> Resolver
              -> Domain
              -> TYPE
              -> IO (Either DNSError [RDATA])
lookupSection section rlv dom typ = (>>= toRDATA) <$> lookupRaw rlv dom typ
  where
    {- CNAME hack
    dom' = if "." `isSuffixOf` dom then dom else dom ++ "."
    correct r = rrname r == dom' && rrtype r == typ
    -}
    correct r = rrtype r == typ
    toRDATA = Right . map rdata . filter correct . section

-- | Look up resource records for a domain, collecting the results
--   from the ANSWER section of the response.
lookup :: Resolver -> Domain -> TYPE -> IO (Either DNSError [RDATA])
lookup = lookupSection answer

-- | Look up resource records for a domain, collecting the results
--   from the AUTHORITY section of the response.
lookupAuth :: Resolver -> Domain -> TYPE -> IO (Either DNSError [RDATA])
lookupAuth = lookupSection authority

{-|
  Looking up a domain and returning an entire DNS Response.
-}
lookupRaw :: Resolver -> Domain -> TYPE -> IO (Either DNSError DNSFormat)
lookupRaw rlv dom typ = do
    seqno <- genId rlv
    sendAll sock (composeQuery seqno [q])
    response <- timeout tm (receive sock)
    return $ case response of
               Nothing -> Left TimeoutExpired
               Just y  -> check seqno y
  where
    sock = dnsSock rlv
    tm = dnsTimeout rlv
    q = makeQuestion dom typ
    check seqno res = do
        let hdr = header res
        if identifier hdr == seqno then
            Right res
          else
            Left SequenceNumberMismatch

#if mingw32_HOST_OS == 1
    -- Windows does not support sendAll in Network.ByteString.Lazy.
    -- This implements sendAll with Haskell Strings.
    sendAll sock bs = do
	sent <- send sock (LB.unpack bs)
	when (sent < fromIntegral (LB.length bs)) $ sendAll sock (LB.drop (fromIntegral sent) bs)
#endif
