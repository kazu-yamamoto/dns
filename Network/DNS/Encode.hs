{-# LANGUAGE RecordWildCards #-}

-- | Encoders for DNS.
module Network.DNS.Encode (
    -- * Encoder
    encode
    -- ** Encoder for Each Part
  , encodeResourceRecord
  , encodeDNSHeader
  , encodeDNSFlags
  , encodeDomain
  , encodeMailbox
  ) where

import Control.Monad.State (State, modify, execState, gets)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import qualified Data.IP
import Data.IP (IP(..), fromIPv4, fromIPv6b, makeAddrRange)

import Network.DNS.Imports
import Network.DNS.StateBinary
import Network.DNS.Types

----------------------------------------------------------------

-- | Encoding DNS query or response.
encode :: DNSMessage -> ByteString
encode = runSPut . putDNSMessage

-- | Encoding DNS flags.
encodeDNSFlags :: DNSFlags -> ByteString
encodeDNSFlags = runSPut . putDNSFlags

-- | Encoding DNS header.
encodeDNSHeader :: DNSHeader -> ByteString
encodeDNSHeader = runSPut . putHeader

-- | Encoding domain.
encodeDomain :: Domain -> ByteString
encodeDomain = runSPut . putDomain

-- | Encoding mailbox.
encodeMailbox :: Mailbox -> ByteString
encodeMailbox = runSPut . putMailbox

-- | Encoding resource record.
encodeResourceRecord :: ResourceRecord -> ByteString
encodeResourceRecord rr = runSPut $ putResourceRecord rr

----------------------------------------------------------------

putDNSMessage :: DNSMessage -> SPut
putDNSMessage msg = putHeader hd
                    <> putNums
                    <> mconcat (map putQuestion qs)
                    <> mconcat (map putResourceRecord an)
                    <> mconcat (map putResourceRecord au)
                    <> mconcat (map putResourceRecord ad)
  where
    putNums = mconcat $ fmap putInt16 [ length qs
                                      , length an
                                      , length au
                                      , length ad
                                      ]
    hm = header msg
    fl = flags hm
    eh = ednsHeader msg
    qs = question msg
    an = answer msg
    au = authority msg
    hd = ifEDNS eh hm $ hm { flags = fl { rcode = rc } }
    rc = ifEDNS eh <$> id <*> nonEDNSrcode $ rcode fl
      where
        nonEDNSrcode code | fromRCODE code < 16 = code
                          | otherwise           = FormatErr
    ad = prependOpt $ additional msg
      where
        prependOpt ads = mapEDNS eh (fromEDNS ads $ fromRCODE rc) ads
          where
            fromEDNS :: AdditionalRecords -> Word16 -> EDNS -> AdditionalRecords
            fromEDNS rrs rc' edns = ResourceRecord name' type' class' ttl' rdata' : rrs
              where
                name'  = BS.singleton '.'
                type'  = OPT
                class' = maxUdpSize `min` (minUdpSize `max` ednsUdpSize edns)
                ttl0'  = fromIntegral (rc' .&. 0xff0) `shiftL` 20
                vers'  = fromIntegral (ednsVersion edns) `shiftL` 16
                ttl'
                  | ednsDnssecOk edns = ttl0' `setBit` 15 .|. vers'
                  | otherwise         = ttl0' .|. vers'
                rdata' = RD_OPT $ ednsOptions edns

putHeader :: DNSHeader -> SPut
putHeader hdr = putIdentifier (identifier hdr)
                <> putDNSFlags (flags hdr)
  where
    putIdentifier = put16

putDNSFlags :: DNSFlags -> SPut
putDNSFlags DNSFlags{..} = put16 word
  where
    set :: Word16 -> State Word16 ()
    set byte = modify (.|. byte)

    st :: State Word16 ()
    st = sequence_
              [ set (fromRCODE rcode .&. 0x0f)
              , when chkDisable          $ set (bit 4)
              , when authenData          $ set (bit 5)
              , when recAvailable        $ set (bit 7)
              , when recDesired          $ set (bit 8)
              , when trunCation          $ set (bit 9)
              , when authAnswer          $ set (bit 10)
              , set (fromOPCODE opcode `shiftL` 11)
              , when (qOrR==QR_Response) $ set (bit 15)
              ]

    word = execState st 0

-- XXX: Use question class when implemented
--
putQuestion :: Question -> SPut
putQuestion Question{..} = putDomain qname
                           <> put16 (fromTYPE qtype)
                           <> put16 classIN

putResourceRecord :: ResourceRecord -> SPut
putResourceRecord ResourceRecord{..} = mconcat [
    putDomain rrname
  , put16 (fromTYPE rrtype)
  , put16 rrclass
  , put32 rrttl
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
    RD_OPT opts     -> mconcat $ fmap putOData opts
    RD_SOA mn mr serial refresh retry expire min' -> mconcat
        [ putDomain mn
        , putMailbox mr
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
    RD_NULL -> pure mempty
    (RD_DNSKEY f p a k) -> mconcat
        [ put16 f
        , put8 p
        , put8 a
        , putByteString k
        ]
    (RD_NSEC3PARAM h f i s) -> mconcat
        [ put8 h
        , put8 f
        , put16 i
        , putByteStringWithLength s
        ]
    UnknownRData bytes -> putByteString bytes

-- | Encode EDNS OPTION consisting of a list of octets.
putODWords :: Word16 -> [Word8] -> SPut
putODWords code ws =
     mconcat [ put16 code
             , putInt16 $ length ws
             , mconcat $ map put8 ws
             ]

-- | Encode an EDNS OPTION byte string.
putODBytes :: Word16 -> ByteString -> SPut
putODBytes code bs =
    mconcat [ put16 code
            , putInt16 $ BS.length bs
            , putByteString bs
            ]

putOData :: OData -> SPut
putOData (OD_NSID nsid) = putODBytes (fromOptCode NSID) nsid
putOData (OD_DAU as) = putODWords (fromOptCode DAU) as
putOData (OD_DHU hs) = putODWords (fromOptCode DHU) hs
putOData (OD_N3U hs) = putODWords (fromOptCode N3U) hs
putOData (OD_ClientSubnet srcBits scpBits ip) =
    -- https://tools.ietf.org/html/rfc7871#section-6
    --
    -- o  ADDRESS, variable number of octets, contains either an IPv4 or
    --    IPv6 address, depending on FAMILY, which MUST be truncated to the
    --    number of bits indicated by the SOURCE PREFIX-LENGTH field,
    --    padding with 0 bits to pad to the end of the last octet needed.
    --
    -- o  A server receiving an ECS option that uses either too few or too
    --    many ADDRESS octets, or that has non-zero ADDRESS bits set beyond
    --    SOURCE PREFIX-LENGTH, SHOULD return FORMERR to reject the packet,
    --    as a signal to the software developer making the request to fix
    --    their implementation.
    --
    let octets = fromIntegral $ (srcBits + 7) `div` 8
        prefix addr = Data.IP.addr $ makeAddrRange addr $ fromIntegral srcBits
        (family, raw) = case ip of
                        IPv4 ip4 -> (1, take octets $ fromIPv4  $ prefix ip4)
                        IPv6 ip6 -> (2, take octets $ fromIPv6b $ prefix ip6)
        dataLen = 2 + 2 + octets
     in mconcat [ put16 $ fromOptCode ClientSubnet
                , putInt16 dataLen
                , put16 family
                , put8 srcBits
                , put8 scpBits
                , mconcat $ fmap putInt8 raw
                ]
putOData (OD_ECSgeneric family srcBits scpBits addr) =
    mconcat [ put16 $ fromOptCode ClientSubnet
            , putInt16 $ 4 + BS.length addr
            , put16 family
            , put8 srcBits
            , put8 scpBits
            , putByteString addr
            ]
putOData (UnknownOData code bs) = putODBytes code bs

-- In the case of the TXT record, we need to put the string length
-- fixme : What happens with the length > 256 ?
putByteStringWithLength :: BS.ByteString -> SPut
putByteStringWithLength bs = putInt8 (fromIntegral $ BS.length bs) -- put the length of the given string
                          <> putByteString bs

----------------------------------------------------------------

rootDomain :: Domain
rootDomain = BS.pack "."

putDomain :: Domain -> SPut
putDomain = putDomain' '.'

putMailbox :: Mailbox -> SPut
putMailbox = putDomain' '@'

putDomain' :: Char -> ByteString -> SPut
putDomain' sep dom
    | BS.null dom || dom == rootDomain = put8 0
    | otherwise = do
        mpos <- wsPop dom
        cur <- gets wsPosition
        case mpos of
            Just pos -> putPointer pos
            Nothing  -> wsPush dom cur >>
                        mconcat [ putPartialDomain hd
                                , putDomain' '.' tl
                                ]
  where
    (hd, tl') = case sep of
        '.' -> BS.break (== '.') dom
        _ | sep `BS.elem` dom -> BS.break (== sep) dom
          | otherwise -> BS.break (== '.') dom
    tl = if BS.null tl' then tl' else BS.drop 1 tl'

putPointer :: Int -> SPut
putPointer pos = putInt16 (pos .|. 0xc000)

putPartialDomain :: Domain -> SPut
putPartialDomain = putByteStringWithLength
