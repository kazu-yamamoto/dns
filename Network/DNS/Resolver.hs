{-|
  DNS Resolver and lookup functions.
-}

module Network.DNS.Resolver (
    ResolvSeed, makeResolvSeed, makeDefaultResolvSeed
  , Resolver, withResolver
  , lookup, lookupRaw
  ) where

import Control.Applicative
import Control.Exception
import Data.List hiding (find, lookup)
import Data.Int
import Network.DNS.Types
import Network.DNS.Query
import Network.DNS.Response
import Random
import Network.BSD
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString.Lazy
import Prelude hiding (lookup)

----------------------------------------------------------------

{-|
  Abstract data type of DNS Resolver seed
-}
data ResolvSeed = ResolvSeed {
    addrInfo :: AddrInfo
}

data Resolver = Resolver {
    genId   :: IO Int
  , dnsSock :: Socket
}

----------------------------------------------------------------

resolvConf :: String
resolvConf = "/etc/resolv.conf"

dnsBufferSize :: Int64
dnsBufferSize = 512

----------------------------------------------------------------

{-|
  Making 'ResolvSeed' from an IP address of a DNS cache server.
-}
makeResolvSeed :: HostName -> IO ResolvSeed
makeResolvSeed addr = ResolvSeed <$> makeAddrInfo addr

{-|
  Making 'ResolvSeed' from \"/etc/resolv.conf\".
-}
makeDefaultResolvSeed :: IO ResolvSeed
makeDefaultResolvSeed = toAddr <$> readFile resolvConf >>= makeResolvSeed
  where
    toAddr cs = let l:_ = filter ("nameserver" `isPrefixOf`) $ lines cs
                in drop 11 l

----------------------------------------------------------------

getRandom :: IO Int
getRandom = getStdRandom (randomR (0,65535))

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

withResolver :: ResolvSeed -> (Resolver -> IO ()) -> IO ()
withResolver seed func = do
  let ai = addrInfo seed
  sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
  connect sock (addrAddress ai)
  let resolv = Resolver getRandom sock
  func resolv `finally` sClose sock

----------------------------------------------------------------

{-|
  Looking up resource records of a domain.
-}
lookup :: Resolver -> Domain -> TYPE -> IO (Maybe [RDATA])
lookup rlv dom typ = do
    let sock = dnsSock rlv
    seqno <- genId rlv
    res <- lookupRaw' sock seqno dom typ
    let hdr = header res
    if identifier hdr == seqno && anCount hdr /= 0
       then return . listToMaybe . map rdata . filter correct $ answer res
       else return Nothing
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

{-|
  Looking up a domain and returning an entire DNS Response.
-}
lookupRaw :: Resolver -> Domain -> TYPE -> IO DNSFormat
lookupRaw rlv dom typ = do
   let sock = dnsSock rlv
   seqno <- genId rlv
   lookupRaw' sock seqno dom typ

lookupRaw' :: Socket -> Int -> Domain -> TYPE -> IO DNSFormat
lookupRaw' sock seqno dom typ = do
  let q = makeQuestion dom typ
  sendAll sock (composeQuery seqno [q])
  parseResponse <$> recv sock dnsBufferSize
