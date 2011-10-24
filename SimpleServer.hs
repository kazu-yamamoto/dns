{-# LANGUAGE RecordWildCards, OverloadedStrings #-}

import System.Environment
import Control.Monad
import Control.Concurrent
import Control.Applicative
import Data.Monoid
import Data.Maybe
import qualified Data.ByteString as S
import Data.ByteString.Lazy hiding (putStrLn, filter, length)
import System.Timeout
import Network.BSD
import Network.DNS hiding (lookup)
import Network.DNS.Response
import Network.DNS.Query
import Network.Socket hiding (recvFrom)
import Network.Socket.ByteString
import Network.Socket.Enumerator
import Data.Default
import Data.IP

data Conf = Conf {
    bufSize :: Int
  , timeOut :: Int
  , realDNS :: HostName
  , hosts   :: [(Domain, IPv4)]
}

-- TODO load hosts from config file
-- TODO support wildcard in hosts
instance Default Conf where
    def = Conf {
        bufSize = 512
      , timeOut = 3 * 1000 * 1000
      , realDNS = "192.168.1.1"
      , hosts   = [("localhost", "127.0.0.1")]
    }

timeout' :: String -> Int -> IO a -> IO (Maybe a)
timeout' msg tm io = do
    result <- timeout tm io
    maybe (putStrLn msg) (const $ return ()) result
    return result

proxyRequest :: Conf -> ResolvConf -> DNSFormat -> IO (Maybe DNSFormat)
proxyRequest Conf{..} rc req = do
    let worker Resolver{..} = do
          let packet = mconcat . toChunks $ composeDNSFormat req
          sendAll dnsSock packet
          let responseEnum = enumSocket dnsBufsize dnsSock
          parseResponse responseEnum responseIter

    rs <- makeResolvSeed rc
    withResolver rs $ \r ->
        (>>= check) <$> timeout' "proxy timeout" timeOut (worker r)
  where
    ident = identifier . header $ req
    check :: DNSFormat -> Maybe DNSFormat
    check rsp = let hdr = header rsp
                in  if identifier hdr == ident
                        then Just rsp
                        else Nothing

handleRequest :: Conf -> ResolvConf -> DNSFormat -> IO (Maybe DNSFormat)
handleRequest conf@Conf{hosts=hosts} rc req =
    maybe
      (proxyRequest conf rc req)
      (return . Just)
      lookupHosts
  where
    filterA = filter ((==A) . qtype)
    ident = identifier . header $ req
    lookupHosts = do
        q <- listToMaybe . filterA . question $ req
        ip <- lookup (qname q) hosts
        return $ responseA ident q ip

handlePacket :: Conf -> Socket -> SockAddr -> S.ByteString -> IO ()
handlePacket conf@Conf{..} sock addr bs = case runDNSFormat_ (fromChunks [bs]) of
    Right req -> do
        let rc = defaultResolvConf { resolvInfo = RCHostName realDNS }
        mrsp <- handleRequest conf rc req
        case mrsp of
            Just rsp ->
                let packet = mconcat . toChunks $ composeDNSFormat rsp
                in  void $ timeout' "send timeout" timeOut (sendAllTo sock packet addr)
            Nothing -> return ()
    Left msg -> putStrLn msg

main :: IO ()
main = withSocketsDo $ do
    dns <- fromMaybe (realDNS def) . listToMaybe <$> getArgs
    let conf = def { realDNS=dns }
    addrinfos <- getAddrInfo 
                   (Just (defaultHints {addrFlags = [AI_PASSIVE]}))
                   Nothing (Just "domain")
    addrinfo <- maybe (fail "no addr info") return (listToMaybe addrinfos)
    sock <- socket (addrFamily addrinfo) Datagram defaultProtocol
    bindSocket sock (addrAddress addrinfo)
    forever $ do
        (bs, addr) <- recvFrom sock (bufSize conf)
        forkIO $ handlePacket conf sock addr bs
