{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}

module Network.DNS.Transport (
    Resolver(..)
  , resolve
  ) where

import Control.Exception as E
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NE
import Data.Typeable
import Data.Word (Word16)
import Network.DNS.IO
import Network.DNS.Types
import Network.Socket (AddrInfo(..), SockAddr(..), Family(AF_INET, AF_INET6), Socket, SocketType(Stream), close, socket, connect, defaultProtocol)
import System.IO.Error (annotateIOError)
import System.Timeout (timeout)

----------------------------------------------------------------

-- | Abstract data type of DNS Resolver
--   When implementing a DNS cache, this MUST NOT be re-used.
data Resolver = Resolver {
    genId      :: IO Word16
  , dnsServers :: NonEmpty AddrInfo
  , dnsTimeout :: Int
  , dnsRetry   :: Int
  , dnsBufsize :: Integer
}

----------------------------------------------------------------

data TCPFallback = TCPFallback deriving (Show, Typeable)
instance Exception TCPFallback

-- Lookup loop, we try UDP until we get a response.  If the response
-- is truncated, we try TCP once, with no further UDP retries.
-- EDNS0 support would significantly reduce the need for TCP retries.
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
resolve rcv ad rlv dom typ = loop (NE.uncons (dnsServers rlv))
  where
    loop (ai, mais) = do
      (query, checkSeqno) <- initialize
      eres <- E.try $ udpTcpLookup query ai tm checkSeqno retry rcv
      case eres of
        Left e  -> case mais of
          Nothing  -> return $ Left e
          Just ais -> loop $ NE.uncons ais
        Right v -> pure (Right v)

    initialize = do
      seqno <- genId rlv
      let compose = if ad then composeQueryAD else composeQuery
          query = compose seqno [q]
          checkSeqno = check seqno
      return (query, checkSeqno)

    tm = dnsTimeout rlv
    retry = dnsRetry rlv
    q = Question dom typ
    check seqno res = identifier (header res) == seqno

----------------------------------------------------------------

udpTcpLookup :: ByteString
             -> AddrInfo
             -> Int
             -> (DNSMessage -> Bool)
             -> Int
             -> (Socket -> IO DNSMessage)
             -> IO DNSMessage
udpTcpLookup query ai tm checkSeqno retry rcv =
    udpLookup query ai tm checkSeqno retry rcv `E.catch` \TCPFallback ->
        tcpLookup query ai tm

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
udpLookup :: ByteString
          -> AddrInfo
          -> Int
          -> (DNSMessage -> Bool)
          -> Int
          -> (Socket -> IO DNSMessage)
          -> IO DNSMessage
udpLookup query ai tm checkSeqno retry rcv =
    E.handle (ioErrorToDNSError ai "UDP") $ bracket (udpOpen ai) close (loop 0 False)
  where
    loop cnt mismatch sock
      | cnt == retry = if mismatch then
                         E.throwIO SequenceNumberMismatch
                       else
                         E.throwIO RetryLimitExceeded
      | otherwise    = do
          mres <- timeout tm (send sock query >> rcv sock)
          case mres of
              Nothing  -> loop (cnt + 1) False sock
              Just res
                | checkSeqno res -> if trunCation $ flags $ header res then
                                      E.throwIO TCPFallback
                                    else
                                      return res
                | otherwise      -> loop (cnt + 1) True sock

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
tcpLookup :: ByteString
          -> AddrInfo
          -> Int
          -> IO DNSMessage
tcpLookup query ai tm =
    E.handle (ioErrorToDNSError ai "TCP") $ bracket (tcpOpen addr) close perform
  where
    addr = addrAddress ai
    perform vc = do
        mres <- timeout tm $ do
            connect vc addr
            sendVC vc query
            receiveVC vc
        case mres of
            Nothing  -> E.throwIO TimeoutExpired
            Just res -> return res

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
