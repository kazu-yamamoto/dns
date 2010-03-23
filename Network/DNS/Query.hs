module Network.DNS.Query (composeQuery) where

import Data.ByteString.Lazy (ByteString)
import Data.Char
import Network.DNS.StateBinary
import Network.DNS.Internal

----------------------------------------------------------------

composeQuery :: Int -> [Question] -> ByteString
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
encodeQuery fmt = do
  let hdr = header fmt
      qs = question fmt
  encodeHeader hdr
  encodeQuestion qs
  return ()

encodeHeader :: DNSHeader -> SPut
encodeHeader hdr = do
    encodeIdentifier $ identifier hdr
    encodeFlags $ flags hdr
    decodeQdCount $ qdCount hdr
    decodeAnCount $ anCount hdr
    decodeNsCount $ nsCount hdr
    decodeArCount $ arCount hdr
  where
    encodeIdentifier = putInt16
    decodeQdCount = putInt16
    decodeAnCount = putInt16
    decodeNsCount = putInt16
    decodeArCount = putInt16

encodeFlags :: DNSFlags -> SPut
encodeFlags _ = put16 0x0100 -- xxx

encodeQuestion :: [Question] -> SPut
encodeQuestion qs = do
  let q = head qs
      dom = qname q
      typ = qtype q
  encodeDomain dom
  putInt16 . typeToInt $ typ
  put16 1

----------------------------------------------------------------

encodeDomain :: Domain -> SPut
encodeDomain dom = do
    let ss = split '.' dom
        ls = map length ss
    mapM_ encodeSubDomain $ zip ls ss
    put8 0
  where
    encodeSubDomain (len,sub) = do
      putInt8 len
      mapM_ (putInt8 . ord) sub

split :: Char -> String -> [String]
split _ "" = []
split c cs
  | null rest = s : split c rest
  | otherwise = s : split c (tail rest)
  where
    (s,rest) = break (c ==) cs
