{-# LANGUAGE RecordWildCards, CPP #-}

module Network.DNS.Encode (
    encode
  , encodeDNSFlags
  , encodeDNSHeader
  , encodeDomain
  , encodeResourceRecord
  , encodeVC
  , composeQuery
  , composeQueryAD
  ) where

import Control.Monad (when)
import Control.Monad.State (State, modify, execState, gets)
import Data.Binary (Word16)
import Data.Bits ((.|.), bit, shiftL, setBit)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.ByteString.Char8 (ByteString)
import Data.IP (IP(..),fromIPv4, fromIPv6b)
import Data.List (dropWhileEnd)
import Data.Monoid ((<>))
import Network.DNS.Internal
import Network.DNS.StateBinary

#if __GLASGOW_HASKELL__ < 709
import Data.Monoid (mconcat)
#endif

----------------------------------------------------------------

-- | Composing query. First argument is a number to identify response.

composeQuery :: Word16 -> [Question] -> ByteString
composeQuery idt qs = encode qry
  where
    hdr = header defaultQuery
    qry = defaultQuery {
        header = hdr {
           identifier = idt
         }
      , question = qs
      }

composeQueryAD :: Word16 -> [Question] -> ByteString
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

-- | Composing DNS data.

encode :: DNSMessage -> ByteString
encode = runSPut . putDNSMessage

encodeVC :: ByteString -> ByteString
encodeVC query =
    let len = LBS.toStrict . BB.toLazyByteString $ BB.int16BE $ fromIntegral $ BS.length query
    in len <> query

encodeDNSFlags :: DNSFlags -> ByteString
encodeDNSFlags = runSPut . putDNSFlags

encodeDNSHeader :: DNSHeader -> ByteString
encodeDNSHeader = runSPut . putHeader

encodeDomain :: Domain -> ByteString
encodeDomain = runSPut . putDomain

encodeResourceRecord :: ResourceRecord -> ByteString
encodeResourceRecord rr = runSPut $ putResourceRecord rr

----------------------------------------------------------------

putDNSMessage :: DNSMessage -> SPut
putDNSMessage msg = putHeader hdr
                    <> putNums
                    <> mconcat (map putQuestion qs)
                    <> mconcat (map putResourceRecord an)
                    <> mconcat (map putResourceRecord au)
                    <> mconcat (map putResourceRecord ad)
  where
    putNums = mconcat $ fmap putInt16 [length qs
                                         ,length an
                                         ,length au
                                         ,length ad
                                         ]
    hdr = header msg
    qs = question msg
    an = answer msg
    au = authority msg
    ad = additional msg

putHeader :: DNSHeader -> SPut
putHeader hdr = putIdentifier (identifier hdr)
                <> putDNSFlags (flags hdr)
  where
    putIdentifier = put16

putDNSFlags :: DNSFlags -> SPut
putDNSFlags DNSFlags{..} = put16 word
  where
    word16 :: Enum a => a -> Word16
    word16 = toEnum . fromEnum

    set :: Word16 -> State Word16 ()
    set byte = modify (.|. byte)

    st :: State Word16 ()
    st = sequence_
              [ set (word16 rcode)
              , when authenData          $ set (bit 5)
              , when recAvailable        $ set (bit 7)
              , when recDesired          $ set (bit 8)
              , when trunCation          $ set (bit 9)
              , when authAnswer          $ set (bit 10)
              , set (word16 opcode `shiftL` 11)
              , when (qOrR==QR_Response) $ set (bit 15)
              ]

    word = execState st 0

putQuestion :: Question -> SPut
putQuestion Question{..} = putDomain qname
                           <> put16 (typeToInt qtype)
                           <> put16 1

putResourceRecord :: ResourceRecord -> SPut
putResourceRecord rr =
    case rr of
        ResourceRecord rrname rrtype rrttl rdata ->
            mconcat [ putDomain rrname
                    , put16 (typeToInt rrtype)
                    , put16 1
                    , put32 rrttl
                    , putResourceRData rdata
                    ]
        OptRecord orudpsize ordnssecok orversion rdata ->
            mconcat [ putDomain BS.empty
                    , put16 (typeToInt OPT)
                    , put16 orudpsize
                    , put8 0   -- ERCode
                    , put8 orversion
                    , putInt16 $ if ordnssecok then setBit 0 15 else 0
                    , putResourceRData rdata
                    ]
  where
    putResourceRData :: RData -> SPut
    putResourceRData rd = do
        addPositionW 2 -- "simulate" putInt16
        rDataBuilder <- putRData rd
        let rdataLength = fromIntegral . LBS.length . BB.toLazyByteString $ rDataBuilder
        let rlenBuilder = BB.int16BE rdataLength
        return $ rlenBuilder <> rDataBuilder


putRData :: RData -> SPut
putRData rd = case rd of
    RD_A ip         -> mconcat $ map putInt8 (fromIPv4 ip)
    RD_AAAA ip      -> mconcat $ map putInt8 (fromIPv6b ip)
    RD_NS dom       -> putDomain dom
    RD_CNAME dom    -> putDomain dom
    RD_DNAME dom    -> putDomain dom
    RD_PTR dom      -> putDomain dom
    RD_MX prf dom   -> mconcat [put16 prf, putDomain dom]
    RD_TXT txt      -> putByteStringWithLength txt
    RD_OTH bytes    -> putByteString bytes
    RD_OPT opts     -> mconcat $ fmap putOData opts
    RD_SOA d1 d2 serial refresh retry expire min' -> mconcat
        [ putDomain d1
        , putDomain d2
        , put32 serial
        , put32 refresh
        , put32 retry
        , put32 expire
        , put32 min'
        ]
    RD_SRV prio weight port dom -> mconcat
        [ put16 prio
        , put16 weight
        , put16 port
        , putDomain dom
        ]
    RD_TLSA u s m d -> mconcat
        [ put8 u
        , put8 s
        , put8 m
        , putByteString d
        ]
    RD_DS t a dt dv -> mconcat
        [ put16 t
        , put8 a
        , put8 dt
        , putByteString dv
        ]

putOData :: OData -> SPut
putOData (OD_ClientSubnet srcNet scpNet ip) =
    let dropZeroes = dropWhileEnd (==0)
        (fam,raw) = case ip of
                        IPv4 ip4 -> (1,dropZeroes $ fromIPv4 ip4)
                        IPv6 ip6 -> (2,dropZeroes $ fromIPv6b ip6)
        dataLen = 2 + 2 + length raw
     in mconcat [ putInt16 (optTypeToInt ClientSubnet)
                , putInt16 dataLen
                , putInt16 fam
                , put8 srcNet
                , put8 scpNet
                , mconcat $ fmap putInt8 raw
                ]
putOData (OD_Unknown code bs) =
    mconcat [ putInt16 code
            , putInt16 $ BS.length bs
            , putByteString bs
            ]

-- In the case of the TXT record, we need to put the string length
-- fixme : What happens with the length > 256 ?
putByteStringWithLength :: BS.ByteString -> SPut
putByteStringWithLength bs = putInt8 (fromIntegral $ BS.length bs) -- put the length of the given string
                          <> putByteString bs

----------------------------------------------------------------

rootDomain :: Domain
rootDomain = BS.pack "."

putDomain :: Domain -> SPut
putDomain dom
    | BS.null dom || dom == rootDomain = put8 0
    | otherwise = do
        mpos <- wsPop dom
        cur <- gets wsPosition
        case mpos of
            Just pos -> putPointer pos
            Nothing  -> wsPush dom cur >>
                        mconcat [ putPartialDomain hd
                                , putDomain tl
                                ]
  where
    (hd, tl') = BS.break (=='.') dom
    tl = if BS.null tl' then tl' else BS.drop 1 tl'

putPointer :: Int -> SPut
putPointer pos = putInt16 (pos .|. 0xc000)

putPartialDomain :: Domain -> SPut
putPartialDomain = putByteStringWithLength
