{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}

module Network.DNS.Transport (
    Resolver(..)
  , resolve
  ) where

import Control.Concurrent.Async (async, waitAnyCancel)
import Control.Exception as E
import qualified Data.ByteString.Char8 as BS
import qualified Data.List.NonEmpty as NE
import Data.Typeable
import Network.Socket (AddrInfo(..), SockAddr(..), Family(AF_INET, AF_INET6), Socket, SocketType(Stream), close, socket, connect, defaultProtocol)
import System.IO.Error (annotateIOError)
import System.Timeout (timeout)

import Network.DNS.IO
import Network.DNS.Types
import Network.DNS.Types.Internal

-- | Check response for a matching identifier.  If we ever do pipelined TCP,
-- we'll also need to match the QNAME, CLASS and QTYPE.  See:
-- https://tools.ietf.org/html/rfc7766#section-7
checkResp :: Question -> Identifier -> DNSMessage -> Bool
checkResp _ seqno resp = identifier (header resp) == seqno

----------------------------------------------------------------

data TCPFallback = TCPFallback deriving (Show, Typeable)
instance Exception TCPFallback

type Rslv0 = Bool -> (Socket -> IO DNSMessage)
           -> IO (Either DNSError DNSMessage)

type Rslv1 = Question
          -> [ResourceRecord]
          -> Int -- Timeout
          -> Int -- Retry
          -> Rslv0

type TcpRslv = Identifier -> AddrInfo -> Question -> Int -- Timeout
            -> Bool -> IO DNSMessage

type UdpRslv = [ResourceRecord] -> Int -- Retry
            -> (Socket -> IO DNSMessage) -> TcpRslv

-- In lookup loop, we try UDP until we get a response.  If the response
-- is truncated, we try TCP once, with no further UDP retries.
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
resolve :: Domain -> TYPE -> Resolver -> Rslv0
resolve dom typ rlv ad rcv
  | isIllegal dom = return $ Left IllegalDomain
  | onlyOne       = resolveOne        (head nss) (head gens) q edns tm retry ad rcv
  | concurrent    = resolveConcurrent nss        gens        q edns tm retry ad rcv
  | otherwise     = resolveSequential nss        gens        q edns tm retry ad rcv
  where
    q = Question dom typ

    gens = NE.toList $ genIds rlv

    seed    = resolvseed rlv
    nss     = NE.toList $ nameservers seed
    onlyOne = length nss == 1

    conf       = resolvconf seed
    concurrent = resolvConcurrent conf
    tm         = resolvTimeout conf
    retry      = resolvRetry conf
    edns       = resolvEDNS conf

resolveSequential :: [AddrInfo] -> [IO Identifier] -> Rslv1
resolveSequential nss gs q edns tm retry ad rcv = loop nss gs
  where
    loop [ai]     [gen] = resolveOne ai gen q edns tm retry ad rcv
    loop (ai:ais) (gen:gens) = do
        eres <- resolveOne ai gen q edns tm retry ad rcv
        case eres of
          Left  _ -> loop ais gens
          res     -> return res
    loop _  _     = error "resolveSequential:loop"

resolveConcurrent :: [AddrInfo] -> [IO Identifier] -> Rslv1
resolveConcurrent nss gens q edns tm retry ad rcv = do
    asyncs <- mapM mkAsync $ zip nss gens
    snd <$> waitAnyCancel asyncs
  where
    mkAsync (ai,gen) = async $ resolveOne ai gen q edns tm retry ad rcv

resolveOne :: AddrInfo -> IO Identifier -> Rslv1
resolveOne ai gen q edns tm retry ad rcv = do
    ident <- gen
    E.try $ udpTcpLookup edns retry rcv ident ai q tm ad

----------------------------------------------------------------

udpTcpLookup :: UdpRslv
udpTcpLookup edns retry rcv ident ai q tm ad =
    udpLookup edns retry rcv ident ai q tm ad `E.catch` \TCPFallback ->
        tcpLookup ident ai q tm ad

----------------------------------------------------------------

ioErrorToDNSError :: AddrInfo -> String -> IOError -> IO DNSMessage
ioErrorToDNSError ai tag ioe = throwIO $ NetworkFailure aioe
  where
    aioe = annotateIOError ioe (show ai) Nothing $ Just tag

----------------------------------------------------------------

udpOpen :: AddrInfo -> IO Socket
udpOpen ai = do
    sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
    connect sock (addrAddress ai)
    return sock

-- This throws DNSError or TCPFallback.
udpLookup :: UdpRslv
udpLookup edns retry rcv ident ai q tm ad = do
    let qry = encodeQuestions ident [q] edns ad
        ednsRetry = not $ null edns
    E.handle (ioErrorToDNSError ai "UDP") $
      bracket (udpOpen ai) close (loop qry ednsRetry 0 RetryLimitExceeded)
  where
    loop qry ednsRetry cnt err sock
      | cnt == retry = E.throwIO err
      | otherwise    = do
          mres <- timeout tm (send sock qry >> rcv sock)
          case mres of
              Nothing  -> loop qry ednsRetry (cnt + 1) RetryLimitExceeded sock
              Just res
                | checkResp q ident res -> do
                      let flgs = flags$ header res
                          truncated = trunCation flgs
                          rc = rcode flgs
                      if truncated then
                          E.throwIO TCPFallback
                      else if ednsRetry && rc == FormatErr then
                          let nonednsQuery = encodeQuestions ident [q] [] ad
                          in loop nonednsQuery False cnt RetryLimitExceeded sock
                      else
                          return res
                | otherwise -> loop qry ednsRetry (cnt + 1) SequenceNumberMismatch sock

----------------------------------------------------------------

-- Create a TCP socket with the given socket address.
tcpOpen :: SockAddr -> IO Socket
tcpOpen peer = case peer of
    SockAddrInet{}  -> socket AF_INET  Stream defaultProtocol
    SockAddrInet6{} -> socket AF_INET6 Stream defaultProtocol
    _               -> E.throwIO ServerFailure

-- Perform a DNS query over TCP, if we were successful in creating
-- the TCP socket.
-- This throws DNSError only.
tcpLookup :: TcpRslv
tcpLookup ident ai q tm ad =
    E.handle (ioErrorToDNSError ai "TCP") $ bracket (tcpOpen addr) close perform
  where
    addr = addrAddress ai
    perform vc = do
        let qry = encodeQuestions ident [q] [] ad
        mres <- timeout tm $ do
            connect vc addr
            sendVC vc qry
            receiveVC vc
        case mres of
            Nothing                     -> E.throwIO TimeoutExpired
            Just res
                | checkResp q ident res -> return res
                | otherwise             -> E.throwIO SequenceNumberMismatch

----------------------------------------------------------------

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
