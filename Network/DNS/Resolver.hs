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
  , resolvBufsize :: Integer
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
  Looking up resource records of a domain.
-}
lookup :: Resolver -> Domain -> TYPE -> IO (Maybe [RDATA])
lookup rlv dom typ = (>>= toRDATA) <$> lookupRaw rlv dom typ
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
    (>>= check seqno) <$> timeout tm (receive sock bufsize)
  where
    sock = dnsSock rlv
    bufsize = dnsBufsize rlv
    tm = dnsTimeout rlv
    q = makeQuestion dom typ
    check seqno res = do
        let hdr = header res
        if identifier hdr == seqno
            then Just res
            else Nothing
