{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.DNS.IO (
    -- * Receiving DNS messages
    receive
  , receiveVC
    -- * Sending pre-encoded messages
  , send
  , sendVC
    -- ** Encoding queries for transmission
  , encodeQuestion
    -- ** Creating query response messages
  , responseA
  , responseAAAA
  ) where

#if !defined(mingw32_HOST_OS)
#define POSIX
#else
#define WIN
#endif

#if __GLASGOW_HASKELL__ < 709
#define GHC708
#endif

import qualified Control.Exception as E
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.Char (ord)
import Data.IP (IPv4, IPv6)
import Network.Socket (Socket)
import System.IO.Error


#if defined(WIN) && defined(GHC708)
import Network.Socket (send, recv)
import qualified Data.ByteString.Char8 as BS
#else
import Network.Socket.ByteString (sendAll, recv)
#endif

import Network.DNS.Decode (decode)
import Network.DNS.Encode (encode)
import Network.DNS.Imports
import Network.DNS.Types

----------------------------------------------------------------

-- | Receiving DNS data from 'Socket' and parse it.

receive :: Socket -> IO DNSMessage
receive sock = do
    let bufsiz = fromIntegral maxUdpSize
    bs <- recv sock bufsiz `E.catch` \e -> E.throwIO $ NetworkFailure e
    case decode bs of
        Left  e   -> E.throwIO e
        Right msg -> return msg

-- | Receive and parse a single virtual-circuit (TCP) query or response.
--   It is up to the caller to implement any desired timeout.

receiveVC :: Socket -> IO DNSMessage
receiveVC sock = do
    len <- toLen <$> recvDNS sock 2
    bs <- recvDNS sock len
    case decode bs of
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

-- | Sending composed query or response to 'Socket'.
send :: Socket -> ByteString -> IO ()
send sock legacyQuery = sendAll sock legacyQuery

-- | Sending composed query or response to a single virtual-circuit (TCP).
sendVC :: Socket -> ByteString -> IO ()
sendVC vc legacyQuery = sendAll vc $ encodeVC legacyQuery

-- | Encoding for virtual circuit.
encodeVC :: ByteString -> ByteString
encodeVC legacyQuery =
    let len = LBS.toStrict . BB.toLazyByteString $ BB.int16BE $ fromIntegral $ BS.length legacyQuery
    in len <> legacyQuery

#if defined(WIN) && defined(GHC708)
-- Windows does not support sendAll in Network.ByteString for older GHCs.
sendAll :: Socket -> BS.ByteString -> IO ()
sendAll sock bs = do
  sent <- send sock (BS.unpack bs)
  when (sent < fromIntegral (BS.length bs)) $ sendAll sock (BS.drop (fromIntegral sent) bs)
#endif

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

----------------------------------------------------------------

-- | Composing a response from IPv4 addresses
responseA :: Identifier -> Question -> [IPv4] -> DNSMessage
responseA idt q ips = makeResponse idt q as
  where
    dom = qname q
    as  = ResourceRecord dom A classIN 300 . RD_A <$> ips

-- | Composing a response from IPv6 addresses
responseAAAA :: Identifier -> Question -> [IPv6] -> DNSMessage
responseAAAA idt q ips = makeResponse idt q as
  where
    dom = qname q
    as  = ResourceRecord dom AAAA classIN 300 . RD_AAAA <$> ips
