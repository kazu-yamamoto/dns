module Network.DNS.Query (composeQuery) where

import qualified Data.ByteString.Lazy.Char8 as BL (ByteString)
import qualified Data.ByteString  as BS (unpack)
import qualified Data.ByteString.Char8 as BS (length, split, null)
import Network.DNS.StateBinary
import Network.DNS.Internal
import Data.Monoid

(+++) :: Monoid a => a -> a -> a
(+++) = mappend

----------------------------------------------------------------

composeQuery :: Int -> [Question] -> BL.ByteString
composeQuery idt qs = runSPut (encodeQuery qry)
  where
    hdr = header defaultQuery
    qry = defaultQuery {
        header = hdr {
           identifier = idt
         , qdCount = length qs
         }
      , question = qs
      }

----------------------------------------------------------------

encodeQuery :: DNSFormat -> SPut
encodeQuery fmt = encodeHeader hdr
              +++ encodeQuestion qs
  where
    hdr = header fmt
    qs = question fmt

encodeHeader :: DNSHeader -> SPut
encodeHeader hdr = encodeIdentifier (identifier hdr)
               +++ encodeFlags (flags hdr)
               +++ decodeQdCount (qdCount hdr)
               +++ decodeAnCount (anCount hdr)
               +++ decodeNsCount (nsCount hdr)
               +++ decodeArCount (arCount hdr)
  where
    encodeIdentifier = putInt16
    decodeQdCount = putInt16
    decodeAnCount = putInt16
    decodeNsCount = putInt16
    decodeArCount = putInt16

encodeFlags :: DNSFlags -> SPut
encodeFlags _ = put16 0x0100 -- xxx

encodeQuestion :: [Question] -> SPut
encodeQuestion qs = encodeDomain dom
                +++ putInt16 (typeToInt typ)
                +++ put16 1
  where
    q = head qs
    dom = qname q
    typ = qtype q

----------------------------------------------------------------

encodeDomain :: Domain -> SPut
encodeDomain dom = foldr ((+++) . encodeSubDomain) (put8 0) $ zip ls ss
  where
    ss = filter (not . BS.null) $ BS.split '.' dom
    ls = map BS.length ss

encodeSubDomain :: (Int, Domain) -> SPut
encodeSubDomain (len,sub) = putInt8 len
                        +++ foldr ((+++) . put8) mempty ss
  where
    ss = BS.unpack sub
