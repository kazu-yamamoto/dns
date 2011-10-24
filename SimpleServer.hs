{-# LANGUAGE RecordWildCards, OverloadedStrings #-}

import Control.Applicative
import Control.Concurrent
import Control.Monad
import qualified Data.ByteString as S
import Data.ByteString.Lazy hiding (putStrLn, filter, length)
import Data.Default
import Data.Maybe
import Data.Monoid
import Debug.Trace
import Network.BSD
import Network.DNS hiding (lookup)
import Network.Socket hiding (recvFrom)
import Network.Socket.ByteString
import System.Environment
import System.Timeout

data Conf = Conf {
    bufSize :: Int
  , timeOut :: Int
  , realDNS :: HostName
}

instance Default Conf where
    def = Conf {
        bufSize = 512
      , timeOut = 3 * 1000 * 1000
      , realDNS = "192.168.1.1"
    }

timeout' :: String -> Int -> IO a -> IO (Maybe a)
timeout' msg tm io = do
    result <- timeout tm io
    maybe (putStrLn msg) (const $ return ()) result
    return result

proxyRequest :: Conf -> ResolvConf -> DNSFormat -> IO (Maybe DNSFormat)
proxyRequest Conf{..} rc req = do
    let
      worker Resolver{..} = do
        let packet = mconcat . toChunks $ encode req
        sendAll dnsSock packet
        receive dnsSock dnsBufsize
    rs <- makeResolvSeed rc
    withResolver rs $ \r ->
        (>>= check) <$> timeout' "proxy timeout" timeOut (worker r)
  where
    ident = identifier . header $ req
    check :: DNSFormat -> Maybe DNSFormat
    check rsp = let hdr = header rsp
                in  if identifier hdr == ident
                        then Just rsp
                        else trace "identifier not match" Nothing

{--
 - TBD
 --}
handleRequest :: Conf -> ResolvConf -> DNSFormat -> IO (Maybe DNSFormat)
handleRequest conf rc req = maybe (proxyRequest conf rc req) (trace "return A record" $ return . Just) mresponse
  where
    filterA = filter ((==A) . qtype)
    mresponse = do
        let ident = identifier . header $ req
        q <- listToMaybe . filterA . question $ req
        let dom = qname q
        ip <- lookup dom hosts
        return $ responseA ident q ip
    hosts = [ ("proxy.com.", "127.0.0.1")
            --, ("*.proxy.com", "127.0.0.1")
            ]

handlePacket :: Conf -> Socket -> SockAddr -> S.ByteString -> IO ()
handlePacket conf@Conf{..} sock addr bs = case decode (fromChunks [bs]) of
    Right req -> do
        print req
        let rc = defaultResolvConf { resolvInfo = RCHostName realDNS }
        mrsp <- handleRequest conf rc req
        print mrsp
        case mrsp of
            Just rsp ->
                let packet = mconcat . toChunks $ encode rsp
                in  timeout' "send timeout" timeOut (sendAllTo sock packet addr) >>
                    print (S.length packet) >>
                    return ()
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
