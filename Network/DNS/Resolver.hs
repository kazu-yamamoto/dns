{-|
  APIs of DNS Resolver.
-}

module Network.DNS.Resolver (
    Resolver, makeResolver, makeDefaultResolver
  , lookup, lookupRaw
  ) where

import Control.Applicative
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
  Abstract data type of DNS Resolver
-}
data Resolver = Resolver {
    genId    :: IO Int
  , addrInfo :: AddrInfo
}

----------------------------------------------------------------

resolvConf :: String
resolvConf = "/etc/resolv.conf"

dnsBufferSize :: Int64
dnsBufferSize = 512

----------------------------------------------------------------

{-|
  Making Resolver from an IP address of a DNS cache server.
-}
makeResolver :: HostName -> IO Resolver
makeResolver addr = do
    ai <- makeAddrInfo addr
    return $ Resolver { genId = getRandom, addrInfo = ai }

{-|
  Making Resolver from \"/etc/resolv.conf\".
-}
makeDefaultResolver :: IO Resolver
makeDefaultResolver = do
  cs <- readFile resolvConf
  let l:_ = filter ("nameserver" `isPrefixOf`) $ lines cs
  makeResolver $ drop 11 l

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

{-|
  Looking up resource records of a domain.
-}
lookup :: Domain -> TYPE -> Resolver -> IO (Maybe [RDATA])
lookup dom typ rlv = do
    idnt <- genId rlv
    res <- lookupRaw' dom typ rlv idnt
    let hdr = header res
    if identifier hdr == idnt && anCount hdr /= 0
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
lookupRaw :: Domain -> TYPE -> Resolver -> IO DNSFormat
lookupRaw dom typ rlv = genId rlv >>= lookupRaw' dom typ rlv

lookupRaw' :: Domain -> TYPE -> Resolver -> Int -> IO DNSFormat
lookupRaw' dom typ rlv idnt = do
  let ai = addrInfo rlv
      q = makeQuestion dom typ
  sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
  connect sock (addrAddress ai)
  sendAll sock (composeQuery idnt [q])
  fmt <- parseResponse <$> recv sock dnsBufferSize
  sClose sock
  return fmt
