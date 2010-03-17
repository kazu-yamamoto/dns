module Network.DNS (
    module Network.DNS.Types
  , lookup, lookupRaw, Resolver
  , makeResolver, makeDefaultResolver
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

makeResolver :: String -> IO Resolver
makeResolver addr = do
    sock <- openSocket addr
    return $ Resolver { genId = getRandom, dnsSock = sock }

makeDefaultResolver :: IO Resolver
makeDefaultResolver = do
  cs <- readFile resolvConf
  let l:_ = filter ("nameserver" `isPrefixOf`) $ lines cs
  makeResolver $ drop 11 l

----------------------------------------------------------------

getRandom :: IO Int
getRandom = getStdRandom (randomR (0,65535))

openSocket :: String -> IO Socket
openSocket addr = do
    proto <- getProtocolNumber "udp"
    let hints = defaultHints {
            addrFlags = [AI_ADDRCONFIG, AI_NUMERICHOST, AI_PASSIVE]
          , addrSocketType = Datagram
          , addrProtocol = proto
          }
    a:_ <- getAddrInfo (Just hints) (Just addr) (Just "domain")
    sock <- socket (addrFamily a) (addrSocketType a) (addrProtocol a)
    connect sock (addrAddress a)
    return sock

----------------------------------------------------------------

lookupRaw :: String -> TYPE -> Resolver -> IO DNSFormat
lookupRaw dom typ rlv = genId rlv >>= lookupRaw' dom typ rlv

lookupRaw' :: String -> TYPE -> Resolver -> Int -> IO DNSFormat
lookupRaw' dom typ rlv idnt = do
  let sock = dnsSock rlv
      q = makeQuestion dom typ
  sendAll sock (composeQuery idnt [q])
  parseResponse <$> recv sock dnsBufferSize

lookup :: String -> TYPE -> Resolver -> IO (Maybe RDATA)
lookup dom typ rlv = do
  idnt <- genId rlv
  res <- lookupRaw' dom typ rlv idnt
  let hdr = header res
  if identifier hdr == idnt && anCount hdr /= 0
     then return $ find dom typ (answer res)
     else return Nothing

find :: Domain -> TYPE -> [ResourceRecord] -> Maybe RDATA
find _ _ [] = Nothing
find dom typ (r:rs)
  | rrname r == dom && rrtype r == typ = return $ rdata r
  | otherwise                          = find dom typ rs
