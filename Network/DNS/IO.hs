{-# LANGUAGE CPP #-}

module Network.DNS.IO (
    -- * Receiving from socket
    receive
  , receiveVC
    -- * Sending to socket
  , send
  , sendVC
    -- ** Creating Query
  , encodeQuestions
  , composeQuery
  , composeQueryAD
    -- ** Creating Response
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

import qualified Control.Monad.State as ST
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.Char (ord)
import Data.Conduit (($$), ($$+), ($$+-), (=$), Sink)
import Data.Conduit.Attoparsec (sinkParser)
import qualified Data.Conduit.Binary as CB
import Data.Conduit.Network (sourceSocket)
import Data.IP (IPv4, IPv6)
import Network (Socket)

#if defined(WIN) && defined(GHC708)
import Network.Socket (send)
import qualified Data.ByteString.Char8 as BS
#else
import Network.Socket.ByteString (sendAll)
#endif

import Network.DNS.Decode.Internal (getResponse)
import Network.DNS.Encode (encode)
import Network.DNS.Imports
import Network.DNS.StateBinary (PState, initialState)
import Network.DNS.Types

----------------------------------------------------------------

sink :: Sink ByteString IO (DNSMessage, PState)
sink = sinkParser $ ST.runStateT getResponse initialState

-- | Receiving DNS data from 'Socket' and parse it.

receive :: Socket -> IO DNSMessage
receive sock = fst <$> (sourceSocket sock $$ sink)

-- | Receive and parse a single virtual-circuit (TCP) query or response.
--   It is up to the caller to implement any desired timeout.

receiveVC :: Socket -> IO DNSMessage
receiveVC sock = do
    (src, lenbytes) <- sourceSocket sock $$+ CB.take 2
    let len = case map ord $ LBS.unpack lenbytes of
                [hi, lo] -> 256 * hi + lo
                _        -> 0
    fst <$> (src $$+- CB.isolate len =$ sink)

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

----------------------------------------------------------------

-- | Creating query.
encodeQuestions :: Identifier
                -> [Question]
                -> [ResourceRecord] -- ^ Additional RRs for EDNS.
                -> Bool             -- ^ Authentication
                -> ByteString
encodeQuestions idt qs adds auth = encode qry
  where
      hdr = header defaultQuery
      flg = flags hdr
      qry = defaultQuery {
          header = hdr {
              identifier = idt,
              flags = flg {
                  authenData = auth
              }
           }
        , question = qs
        , additional = adds
        }

{-# DEPRECATED composeQuery "Use encodeQuestions instead" #-}
-- | Composing query without EDNS0.
composeQuery :: Identifier -> [Question] -> ByteString
composeQuery idt qs = encodeQuestions idt qs [] False

{-# DEPRECATED composeQueryAD "Use encodeQuestions instead" #-}
-- | Composing query with authentic data flag set without EDNS0.
composeQueryAD :: Identifier -> [Question] -> ByteString
composeQueryAD idt qs = encodeQuestions idt qs [] True

----------------------------------------------------------------

-- | Composing a response from IPv4 addresses
responseA :: Identifier -> Question -> [IPv4] -> DNSMessage
responseA ident q ips =
  let hd = header defaultResponse
      dom = qname q
      an = ResourceRecord dom A classIN 300 . RD_A <$> ips
  in  defaultResponse {
          header = hd { identifier=ident }
        , question = [q]
        , answer = an
      }

-- | Composing a response from IPv6 addresses
responseAAAA :: Identifier -> Question -> [IPv6] -> DNSMessage
responseAAAA ident q ips =
  let hd = header defaultResponse
      dom = qname q
      an = ResourceRecord dom AAAA classIN 300 . RD_AAAA <$> ips
  in  defaultResponse {
          header = hd { identifier=ident }
        , question = [q]
        , answer = an
      }
