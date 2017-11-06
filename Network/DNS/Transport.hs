{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}

module Network.DNS.Transport (
    Resolver(..)
  , resolve
  ) where

import Control.Exception as E
import qualified Data.ByteString.Char8 as BS
import qualified Data.List.NonEmpty as NE
import Data.Typeable
import Data.Word (Word16)
import Network.DNS.IO
import Network.DNS.Types
import Network.DNS.Types.Internal
import Network.Socket (AddrInfo(..), SockAddr(..), Family(AF_INET, AF_INET6), Socket, SocketType(Stream), close, socket, connect, defaultProtocol)
import System.IO.Error (annotateIOError)
import System.Timeout (timeout)

-- | Check response for a matching identifier.  If we ever do pipelined TCP,
-- we'll also need to match the QNAME, CLASS and QTYPE.  See:
-- https://tools.ietf.org/html/rfc7766#section-7
checkResp :: Question -> Word16 -> DNSMessage -> Bool
checkResp _ seqno resp = identifier (header resp) == seqno

----------------------------------------------------------------

data TCPFallback = TCPFallback deriving (Show, Typeable)
instance Exception TCPFallback

-- Lookup loop, we try UDP until we get a response.  If the response
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
resolve :: (Socket -> IO DNSMessage)
        -> Bool
        -> Resolver
        -> Domain
        -> TYPE
        -> IO (Either DNSError DNSMessage)
resolve _ _ _   dom _
  | isIllegal dom     = return $ Left IllegalDomain
resolve rcv ad rlv dom typ = loop $ NE.uncons nss
  where
    loop (ai, mais) = do
        seqno <- genId rlv
        eres <- E.try $ udpTcpLookup q seqno edns0 ad ai tm retry rcv
        case eres of
          Left e  -> case mais of
            Nothing  -> return $ Left e
            Just ais -> loop $ NE.uncons ais
          Right v -> pure (Right v)

    seed  = resolvseed rlv
    nss   = nameservers seed
    conf  = resolvconf seed
    tm    = resolvTimeout conf
    retry = resolvRetry conf
    edns0  = resolvEDNS conf
    q = Question dom typ


----------------------------------------------------------------

udpTcpLookup :: Question
             -> Word16
             -> [ResourceRecord]
             -> Bool
             -> AddrInfo
             -> Int
             -> Int
             -> (Socket -> IO DNSMessage)
             -> IO DNSMessage
udpTcpLookup q seqno edns0 ad ai tm retry rcv =
    udpLookup q seqno edns0 ad ai tm retry rcv `E.catch` \TCPFallback ->
        tcpLookup q seqno ad ai tm

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
udpLookup :: Question
          -> Word16
          -> [ResourceRecord]
          -> Bool
          -> AddrInfo
          -> Int
          -> Int
          -> (Socket -> IO DNSMessage)
          -> IO DNSMessage
udpLookup q seqno edns0 ad ai tm retry rcv = do
    let qry = encodeQuestions seqno [q] edns0 ad
        ednsRetry = not $ null edns0
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
                | checkResp q seqno res -> do
                      let flgs = flags$ header res
                          truncated = trunCation flgs
                          rc = rcode flgs
                      if truncated then
                          E.throwIO TCPFallback
                      else if ednsRetry && (rc == FormatErr || rc == NotImpl)
                      then
                          -- XXX: work-around, NotImpl is NOT a valid response
                          -- to unsupported EDNS requests, but some broken
                          -- nameserveers do it anyway.  The 'NotImpl' case
                          -- should be removed when the bad practice is no
                          -- longer an issue.  Note, we are doing recursive
                          -- queries, and the known bad servers are believed
                          -- authoritative.  It is not clear whether the
                          -- problem is in fact still an issue for any
                          -- recursive servers.
                          let nonednsQuery = encodeQuestions seqno [q] [] ad
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
tcpLookup :: Question
          -> Word16
          -> Bool
          -> AddrInfo
          -> Int
          -> IO DNSMessage
tcpLookup q seqno ad ai tm =
    E.handle (ioErrorToDNSError ai "TCP") $ bracket (tcpOpen addr) close perform
  where
    addr = addrAddress ai
    perform vc = do
        let qry = encodeQuestions seqno [q] [] ad
        mres <- timeout tm $ do
            connect vc addr
            sendVC vc qry
            receiveVC vc
        case mres of
            Nothing  -> E.throwIO TimeoutExpired
            Just res
                | checkResp q seqno res -> return res
                | otherwise -> E.throwIO SequenceNumberMismatch

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
