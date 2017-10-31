{-# LANGUAGE CPP #-}

module Network.DNS.IO (
    -- * Receiving from socket
    receive
  , receiveVC
    -- * Sending to socket
  , send
  , sendVC
    -- ** Composing Query
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

import Control.Monad.Trans.Resource (ResourceT, runResourceT)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.Char (ord)
import Data.Conduit (($$), ($$+), ($$+-), (=$), Source)
import qualified Data.Conduit.Binary as CB
import Data.Conduit.Network (sourceSocket)
import Data.IP (IPv4, IPv6)
import Data.Monoid ((<>))
import Network (Socket)

#ifdef GHC708
import Control.Applicative ((<$>))
#endif

#if defined(WIN) && defined(GHC708)
import Network.Socket (send)
import qualified Data.ByteString.Char8 as BS
import Control.Monad (when)
#else
import Network.Socket.ByteString (sendAll)
#endif

import Network.DNS.Types
import Network.DNS.Encode (encode)
import Network.DNS.Decode.Internal (getResponse)
import Network.DNS.StateBinary (sinkSGet)

----------------------------------------------------------------

-- | Receiving DNS data from 'Socket' and parse it.

receive :: Socket -> IO DNSMessage
receive = receiveDNSFormat . sourceSocket

-- | Receive and parse a single virtual-circuit (TCP) query or response.
--   It is up to the caller to implement any desired timeout.

receiveVC :: Socket -> IO DNSMessage
receiveVC sock = runResourceT $ do
    (src, lenbytes) <- sourceSocket sock $$+ CB.take 2
    let len = case map ord $ LBS.unpack lenbytes of
                [hi, lo] -> 256 * hi + lo
                _        -> 0
    fmap fst (src $$+- CB.isolate len =$ sinkSGet getResponse)

----------------------------------------------------------------

receiveDNSFormat :: Source (ResourceT IO) ByteString -> IO DNSMessage
receiveDNSFormat src = fst <$> runResourceT (src $$ sink)
  where
    sink = sinkSGet getResponse

----------------------------------------------------------------

-- | Sending composed query or response to 'Socket'.
send :: Socket -> ByteString -> IO ()
send sock query = sendAll sock query

-- | Sending composed query or response to a single virtual-circuit (TCP).
sendVC :: Socket -> ByteString -> IO ()
sendVC vc query = sendAll vc $ encodeVC query

-- | Encoding for virtual circuit.
encodeVC :: ByteString -> ByteString
encodeVC query =
    let len = LBS.toStrict . BB.toLazyByteString $ BB.int16BE $ fromIntegral $ BS.length query
    in len <> query

#if defined(WIN) && defined(GHC708)
-- Windows does not support sendAll in Network.ByteString for older GHCs.
sendAll :: Socket -> BS.ByteString -> IO ()
sendAll sock bs = do
  sent <- send sock (BS.unpack bs)
  when (sent < fromIntegral (BS.length bs)) $ sendAll sock (BS.drop (fromIntegral sent) bs)
#endif

----------------------------------------------------------------

-- | Composing query.
composeQuery :: Identifier -> [Question] -> ByteString
composeQuery idt qs = encode qry
  where
    hdr = header defaultQuery
    qry = defaultQuery {
        header = hdr {
           identifier = idt
         }
      , question = qs
      }

-- | Composing query with authentic data flag set.
composeQueryAD :: Identifier -> [Question] -> ByteString
composeQueryAD idt qs = encode qry
  where
      hdr = header defaultQuery
      flg = flags hdr
      qry = defaultQuery {
          header = hdr {
              identifier = idt,
              flags = flg {
                  authenData = True
              }
           }
        , question = qs
        }


----------------------------------------------------------------

-- | Composing a response from IPv4 addresses
responseA :: Identifier -> Question -> [IPv4] -> DNSMessage
responseA ident q ips =
  let hd = header defaultResponse
      dom = qname q
      an = fmap (ResourceRecord dom A classIN 300 . RD_A) ips
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
      an = fmap (ResourceRecord dom AAAA classIN 300 . RD_AAAA) ips
  in  defaultResponse {
          header = hd { identifier=ident }
        , question = [q]
        , answer = an
      }
