{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.DNS.IO (
    -- * Receiving DNS messages
    receive
  , receiveVC
    -- * Sending pre-encoded messages
  , send
  , sendVC
  , sendAll
    -- ** Encoding queries for transmission
  , encodeQuestion
  , encodeVC
    -- ** Creating query response messages
  , responseA
  , responseAAAA
  ) where

import qualified Control.Exception as E
import Control.Monad (void)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.Char (ord)
import Data.IP (IPv4, IPv6)
import Time.System (timeCurrent)
import Time.Types (Elapsed(..), Seconds(..))
import Network.Socket (Socket)
import Network.Socket.ByteString (recv)
import qualified Network.Socket.ByteString as Socket
import System.IO.Error


import Network.DNS.Decode (decodeAt)
import Network.DNS.Encode (encode)
import Network.DNS.Imports
import Network.DNS.Types

----------------------------------------------------------------

-- | Receive and decode a single 'DNSMessage' from a UDP 'Socket'.  Messages
-- longer than 'maxUdpSize' are silently truncated, but this should not occur
-- in practice, since we cap the advertised EDNS UDP buffer size limit at the
-- same value.  A 'DNSError' is raised if I/O or message decoding fails.
--
receive :: Socket -> IO DNSMessage
receive sock = do
    let bufsiz = fromIntegral maxUdpSize
    bs <- recv sock bufsiz `E.catch` \e -> E.throwIO $ NetworkFailure e
    Elapsed (Seconds now) <- timeCurrent
    case decodeAt (fromIntegral now) bs of
        Left  e   -> E.throwIO e
        Right msg -> return msg

-- | Receive and decode a single 'DNSMesage' from a virtual-circuit (TCP).  It
-- is up to the caller to implement any desired timeout. An 'DNSError' is
-- raised if I/O or message decoding fails.
--
receiveVC :: Socket -> IO DNSMessage
receiveVC sock = do
    len <- toLen <$> recvDNS sock 2
    bs <- recvDNS sock len
    Elapsed (Seconds now) <- timeCurrent
    case decodeAt (fromIntegral now) bs of
        Left e    -> E.throwIO e
        Right msg -> return msg
  where
    toLen bs = case map ord $ BS.unpack bs of
        [hi, lo] -> 256 * hi + lo
        _        -> 0              -- never reached

recvDNS :: Socket -> Int -> IO ByteString
recvDNS sock len = recv1 `E.catch` \e -> E.throwIO $ NetworkFailure e
  where
    recv1 = do
        bs1 <- recvCore len
        if BS.length bs1 == len then
            return bs1
          else do
            loop bs1
    loop bs0 = do
        let left = len - BS.length bs0
        bs1 <- recvCore left
        let bs = bs0 `BS.append` bs1
        if BS.length bs == len then
            return bs
          else
            loop bs
    eofE = mkIOError eofErrorType "connection terminated" Nothing Nothing
    recvCore len0 = do
        bs <- recv sock len0
        if bs == "" then
            E.throwIO eofE
          else
            return bs

----------------------------------------------------------------

-- | Send an encoded 'DNSMessage' datagram over UDP.  The message length is
-- implicit in the size of the UDP datagram.  With TCP you must use 'sendVC',
-- because TCP does not have message boundaries, and each message needs to be
-- prepended with an explicit length.  The socket must be explicitly connected
-- to the destination nameserver.
--
send :: Socket -> ByteString -> IO ()
send = (void .). Socket.send
{-# INLINE send #-}

-- | Send a single encoded 'DNSMessage' over TCP.  An explicit length is
-- prepended to the encoded buffer before transmission.  If you want to
-- send a batch of multiple encoded messages back-to-back over a single
-- TCP connection, and then loop to collect the results, use 'encodeVC'
-- to prefix each message with a length, and then use 'sendAll' to send
-- a concatenated batch of the resulting encapsulated messages.
--
sendVC :: Socket -> ByteString -> IO ()
sendVC = (. encodeVC). sendAll
{-# INLINE sendVC #-}

-- | Send one or more encoded 'DNSMessage' buffers over TCP, each allready
-- encapsulated with an explicit length prefix (perhaps via 'encodeVC') and
-- then concatenated into a single buffer.  DO NOT use 'sendAll' with UDP.
--
sendAll :: Socket -> BS.ByteString -> IO ()
sendAll = Socket.sendAll
{-# INLINE sendAll #-}

-- | The encoded 'DNSMessage' has the specified request ID.  The default values
-- of the RD, AD, CD and DO flag bits, as well as various EDNS features, can be
-- adjusted via the 'QueryControls' parameter.
--
-- The caller is responsible for generating the ID via a securely seeded
-- CSPRNG.
--
encodeQuestion :: Identifier     -- ^ Crypto random request id
                -> Question      -- ^ Query name and type
                -> QueryControls -- ^ Query flag and EDNS overrides
                -> ByteString
encodeQuestion idt q ctls = encode $ makeQuery idt q ctls

-- | Encapsulate an encoded 'DNSMessage' buffer for transmission over a TCP
-- virtual circuit.  With TCP the buffer needs to start with an explicit
-- length (the length is implicit with UDP).
--
encodeVC :: ByteString -> ByteString
encodeVC legacyQuery =
    let len = LBS.toStrict . BB.toLazyByteString $ BB.int16BE $ fromIntegral $ BS.length legacyQuery
    in len <> legacyQuery
{-# INLINE encodeVC #-}

----------------------------------------------------------------

-- | Compose a response with a single IPv4 RRset.  If the query
-- had an EDNS pseudo-header, a suitable EDNS pseudo-header must
-- be added to the response message, or else a 'FormatErr' response
-- must be sent.  The response TTL defaults to 300 seconds, and
-- should be updated (to the same value across all the RRs) if some
-- other TTL value is more appropriate.
--
responseA :: Identifier -> Question -> [IPv4] -> DNSMessage
responseA idt q ips = makeResponse idt q as
  where
    dom = qname q
    as  = ResourceRecord dom A classIN 300 . RD_A <$> ips

-- | Compose a response with a single IPv6 RRset.  If the query
-- had an EDNS pseudo-header, a suitable EDNS pseudo-header must
-- be added to the response message, or else a 'FormatErr' response
-- must be sent.  The response TTL defaults to 300 seconds, and
-- should be updated (to the same value across all the RRs) if some
-- other TTL value is more appropriate.
--
responseAAAA :: Identifier -> Question -> [IPv6] -> DNSMessage
responseAAAA idt q ips = makeResponse idt q as
  where
    dom = qname q
    as  = ResourceRecord dom AAAA classIN 300 . RD_AAAA <$> ips
