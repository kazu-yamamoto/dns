{-# LANGUAGE OverloadedStrings #-}

import Control.Applicative
import Control.Concurrent
import Control.Monad
import Data.IP (IPv4)
import Data.Maybe
import Network.DNS hiding (lookup)
import Network.Socket hiding (recvFrom)
import Network.Socket.ByteString
import System.Environment
import System.Timeout
import qualified Data.ByteString as S

data Conf = Conf {
    bufSize :: Int
  , timeOut :: Int
  , realDNS :: HostName
  , hosts   :: [(Domain, IPv4)]
}

defaultConf :: Conf
defaultConf = Conf {
    bufSize = 512
  , timeOut = 3 * 1000 * 1000
  , realDNS = "8.8.8.8"
  , hosts   = [("localhost.", "127.0.0.1")]
  }

timeout' :: String -> Int -> IO a -> IO (Maybe a)
timeout' msg tm io = do
    result <- timeout tm io
    case result of
      Nothing -> putStrLn msg
      Just _  -> return ()
    return result

proxyRequest :: Conf -> DNSMessage -> IO (Maybe DNSMessage)
proxyRequest conf req = do
    sock <- openSocket (realDNS conf) False
    mrsp <- timeout' "proxy timeout" (timeOut conf) $ worker sock
    close sock
    case mrsp of
      Nothing  -> return Nothing
      Just rsp -> return $ check rsp
  where
    worker sock = do
        sendAll sock $ encode req
        receive sock
    ident = identifier . header $ req
    check :: DNSMessage -> Maybe DNSMessage
    check rsp
      | identifier (header rsp) == ident = Just rsp
      | otherwise                        = Nothing

lookupHosts :: Conf -> DNSMessage -> Maybe DNSMessage
lookupHosts conf req = do
    q <- listToMaybe . filterA . question $ req
    ip <- lookup (qname q) $ hosts conf
    return $ responseA ident q [ip]
  where
    filterA = filter ((== A) . qtype)
    ident = identifier . header $ req

handleRequest :: Conf -> DNSMessage -> IO (Maybe DNSMessage)
handleRequest conf req = case lookupHosts conf req of
  Nothing  -> proxyRequest conf req
  Just rsp -> return $ Just rsp

handlePacket :: Conf -> Socket -> SockAddr -> S.ByteString -> IO ()
handlePacket conf sock addr bs = case decode bs of
    Left msg  -> putStrLn msg
    Right req -> do
        mrsp <- handleRequest conf req
        case mrsp of
            Nothing  -> return ()
            Just rsp -> do
                let pkt = encode rsp
                    tout = timeOut conf
                void $ timeout' "send timeout" tout $ sendAllTo sock pkt addr

openSocket :: HostName -> Bool -> IO Socket
openSocket host passive = do
    let hints
          | passive   = defaultHints {addrFlags = [AI_PASSIVE]}
          | otherwise = defaultHints
    addrinfos <- getAddrInfo (Just hints) (Just host) (Just "domain")
    addrinfo <- maybe (fail "no addr info") return (listToMaybe addrinfos)
    sock <- socket (addrFamily addrinfo) Datagram defaultProtocol
    let addr = addrAddress addrinfo
    if passive then
       bind sock addr
    else
       connect sock addr
    return sock

main :: IO ()
main = withSocketsDo $ do
    sock <- openSocket "127.0.0.1" True
    dns <- fromMaybe (realDNS defaultConf) . listToMaybe <$> getArgs
    let conf = defaultConf { realDNS = dns }
    forever $ do
        (bs, addr) <- recvFrom sock (bufSize conf)
        forkIO $ handlePacket conf sock addr bs
