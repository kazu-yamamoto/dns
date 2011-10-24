{-# LANGUAGE RecordWildCards #-}
module Network.DNS.Encode (
    encode
  , composeQuery
  ) where

import qualified Data.ByteString.Lazy.Char8 as BL (ByteString)
import qualified Data.ByteString.Char8 as BS (length, null, break, drop)
import Network.DNS.StateBinary
import Network.DNS.Internal
import Data.Monoid
import Control.Monad.State
import Data.Bits
import Data.Word
import Data.IP

(+++) :: Monoid a => a -> a -> a
(+++) = mappend

----------------------------------------------------------------

{-| Composing query. First argument is a number to identify response.
-}
composeQuery :: Int -> [Question] -> BL.ByteString
composeQuery idt qs = encode qry
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

{-| Composing DNS data.
-}
encode :: DNSFormat -> BL.ByteString
encode fmt = runSPut (encodeDNSFormat fmt)

----------------------------------------------------------------

encodeDNSFormat :: DNSFormat -> SPut
encodeDNSFormat fmt = encodeHeader hdr
                  +++ mconcat (map encodeQuestion qs)
                  +++ mconcat (map encodeRR an)
                  +++ mconcat (map encodeRR au)
                  +++ mconcat (map encodeRR ad)
  where
    hdr = header fmt
    qs = question fmt
    an = answer fmt
    au = authority fmt
    ad = additional fmt

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
encodeFlags DNSFlags{..} = put16 word
  where
    word16 :: Enum a => a -> Word16
    word16 = toEnum . fromEnum

    set :: Word16 -> State Word16 ()
    set byte = modify (.|. byte)

    st :: State Word16 ()
    st = sequence_
              [ set (word16 rcode)
              , when recAvailable        $ set (bit 7)
              , when recDesired          $ set (bit 8)
              , when trunCation          $ set (bit 9)
              , when authAnswer          $ set (bit 10)
              , set (word16 opcode `shiftL` 11)
              , when (qOrR==QR_Response) $ set (bit 15)
              ]

    word = execState st 0

encodeQuestion :: Question -> SPut
encodeQuestion Question{..} =
        encodeDomain qname
    +++ putInt16 (typeToInt qtype)
    +++ put16 1

encodeRR :: ResourceRecord -> SPut
encodeRR ResourceRecord{..} =
    mconcat
      [ encodeDomain rrname
      , putInt16 (typeToInt rrtype)
      , put16 1
      , putInt32 rrttl
      , putInt16 rdlen
      , encodeRDATA rdata
      ]

encodeRDATA :: RDATA -> SPut
encodeRDATA rd = case rd of
    (RD_A ip)          -> mconcat $ map putInt8 (fromIPv4 ip)
    (RD_AAAA ip)       -> mconcat $ map putInt16 (fromIPv6 ip)
    (RD_NS dom)        -> encodeDomain dom
    (RD_CNAME dom)     -> encodeDomain dom
    (RD_PTR dom)       -> encodeDomain dom
    (RD_MX prf dom)    -> mconcat [putInt16 prf, encodeDomain dom]
    (RD_TXT txt)       -> putByteString txt
    (RD_OTH bytes)     -> mconcat $ map putInt8 bytes
    (RD_SOA d1 d2 serial refresh retry expire min') -> mconcat
        [ encodeDomain d1
        , encodeDomain d2
        , putInt32 serial
        , putInt32 refresh
        , putInt32 retry
        , putInt32 expire
        , putInt32 min'
        ]
    (RD_SRV prio weight port dom) -> mconcat
        [ putInt16 prio
        , putInt16 weight
        , putInt16 port
        , encodeDomain dom
        ]

----------------------------------------------------------------

encodeDomain :: Domain -> SPut
encodeDomain dom | BS.null dom = put8 0
encodeDomain dom = do
    mpos <- wsPop dom
    cur <- gets wsPosition
    case mpos of
        Just pos -> encodePointer pos
        Nothing  -> wsPush dom cur >>
                    mconcat [ encodePartialDomain hd
                            , encodeDomain tl
                            ]
  where
    (hd, tl') = BS.break (=='.') dom
    tl = if BS.null tl' then tl' else BS.drop 1 tl'

encodePointer :: Int -> SPut
encodePointer pos = let w = (pos .|. 0xc000) in putInt16 w

encodePartialDomain :: Domain -> SPut
encodePartialDomain sub = putInt8 (BS.length sub)
                      +++ putByteString sub
