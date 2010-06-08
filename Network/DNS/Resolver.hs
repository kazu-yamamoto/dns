{-|
  DNS Resolver and lookup functions.
-}

module Network.DNS.Resolver (
    FileOrNumericHost(..), ResolvConf(..), defaultResolvConf
  , ResolvSeed, makeResolvSeed
  , Resolver, withResolver
  , lookup, lookupRaw
  ) where

import Control.Applicative
import Control.Exception
import Data.Int
import Data.List hiding (find, lookup)
import Network.BSD
import Network.DNS.Query
import Network.DNS.Response
import Network.DNS.Types
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString.Lazy
import Prelude hiding (lookup)
import Random
import System.Timeout

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
  , resolvBufsize :: Int64
}

{-|
  Default 'ResolvConf'.
  'resolvInfo' is 'RCFilePath' \"\/etc\/resolv.conf\".
  'resolvTimeout' is 3,000,000 micro seconds.
  'resolvBufsize' is 512.
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
  , rsBufsize :: Int64
}

{-|
  Abstract data type of DNS Resolver
-}
data Resolver = Resolver {
    genId   :: IO Int
  , dnsSock :: Socket
  , dnsTimeout :: Int
  , dnsBufsize :: Int64
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
                in drop 11 l

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

withResolver :: ResolvSeed -> (Resolver -> IO ()) -> IO ()
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
  Looking up resource records of a domain.
-}
lookup :: Resolver -> Domain -> TYPE -> IO (Maybe [RDATA])
lookup rlv dom typ = do
    mres <- lookupRaw rlv dom typ
    return (mres >>= toRDATA)
  where
    {- CNAME hack
    dom' = if "." `isSuffixOf` dom
           then dom
           else dom ++ "."
    correct r = rrname r == dom' && rrtype r == typ
    -}
    correct r = rrtype r == typ
    listToMaybe [] = Nothing
    listToMaybe xs = Just xs
    toRDATA = listToMaybe . map rdata . filter correct . answer

{-|
  Looking up a domain and returning an entire DNS Response.
-}
lookupRaw :: Resolver -> Domain -> TYPE -> IO (Maybe DNSFormat)
lookupRaw rlv dom typ = do
    seqno <- genId rlv
    sendAll sock (composeQuery seqno [q])
    mres <- timeout tm (parseResponse <$> recv sock bufsize)
    return (mres >>= check seqno)
  where
    sock = dnsSock rlv
    bufsize = dnsBufsize rlv
    tm = dnsTimeout rlv
    q = makeQuestion dom typ
    check seqno res = do
        let hdr = header res
        if identifier hdr == seqno && anCount hdr /= 0
            then Just res
            else Nothing
