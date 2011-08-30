module Network.DNS.Query (composeQuery) where

import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import Network.DNS.StateBinary
import Network.DNS.Internal
import Data.Monoid

(+++) :: Monoid a => a -> a -> a
(+++) = mappend

----------------------------------------------------------------

composeQuery :: Int -> [Question] -> L.ByteString
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
    encodeIdentifier = putInt16 . fromIntegral
    decodeQdCount = putInt16 . fromIntegral
    decodeAnCount = putInt16 . fromIntegral
    decodeNsCount = putInt16 . fromIntegral
    decodeArCount = putInt16 . fromIntegral

encodeFlags :: DNSFlags -> SPut
encodeFlags _ = put16 0x0100 -- xxx

encodeQuestion :: [Question] -> SPut
encodeQuestion qs = encodeDomain dom
                +++ putInt16 (fromIntegral (typeToInt typ))
                +++ put16 1
  where
    q = head qs
    dom = qname q
    typ = qtype q

----------------------------------------------------------------

encodeDomain :: Domain -> SPut
encodeDomain dom = foldr (+++) (put8 0) (map encodeSubDomain $ zip ls ss)
  where
    ss = split '.' dom
    ls = map length ss
    encodeSubDomain (len,sub) = putInt8 (fromIntegral len)
                            +++ foldr (+++) mempty (map (putInt8 . fromIntegral . ord) sub)

split :: Char -> String -> [String]
split _ "" = []
split c cs
  | null rest = s : split c rest
  | otherwise = s : split c (tail rest)
  where
    (s,rest) = break (c ==) cs
