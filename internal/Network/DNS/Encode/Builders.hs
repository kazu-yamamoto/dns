{-# LANGUAGE
    BangPatterns
  , RecordWildCards
  , TransformListComp
  #-}

-- | DNS Message builder.
module Network.DNS.Encode.Builders (
    putDNSMessage
  , putDNSFlags
  , putHeader
  , putDomain
  , putMailbox
  , putResourceRecord
  ) where

import Control.Monad.State (State, modify, execState, gets)
import qualified Control.Exception as E
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import qualified Data.IP
import Data.IP (IP(..), fromIPv4, fromIPv6b, makeAddrRange)
import GHC.Exts (the, groupWith)

import Network.DNS.Imports
import Network.DNS.StateBinary
import Network.DNS.Types.Internal

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
    RD_A                 address -> mconcat $ map putInt8 (fromIPv4 address)
    RD_NS                nsdname -> putDomain nsdname
    RD_CNAME               cname -> putDomain cname
    RD_SOA         a b c d e f g -> putSOA a b c d e f g
    RD_NULL                bytes -> putByteString bytes
    RD_PTR              ptrdname -> putDomain ptrdname
    RD_MX              pref exch -> mconcat [put16 pref, putDomain exch]
    RD_TXT            textstring -> putTXT textstring
    RD_RP             mbox dname -> putMailbox mbox <> putDomain dname
    RD_AAAA              address -> mconcat $ map putInt8 (fromIPv6b address)
    RD_SRV       pri wei prt tgt -> putSRV pri wei prt tgt
    RD_DNAME               dname -> putDomain dname
    RD_OPT               options -> mconcat $ fmap putOData options
    RD_DS             kt ka dt d -> putDS kt ka dt d
    RD_CDS            kt ka dt d -> putDS kt ka dt d
    RD_RRSIG               rrsig -> putRRSIG rrsig
    RD_NSEC           next types -> putDomain next <> putNsecTypes types
    RD_DNSKEY        f p alg key -> putDNSKEY f p alg key
    RD_CDNSKEY       f p alg key -> putDNSKEY f p alg key
    RD_NSEC3     a f i s h types -> putNSEC3 a f i s h types
    RD_NSEC3PARAM  a f iter salt -> putNSEC3PARAM a f iter salt
    RD_TLSA           u s m dgst -> putTLSA u s m dgst
    RD_CAA                 f t v -> putCAA f t v
    UnknownRData           bytes -> putByteString bytes
  where
    putSOA mn mr serial refresh retry expire minttl = mconcat
        [ putDomain mn
        , putMailbox mr
        , put32 serial
        , put32 refresh
        , put32 retry
        , put32 expire
        , put32 minttl
        ]
    -- TXT record string fragments are at most 255 bytes
    putTXT textstring =
        let (!h, !t) = BS.splitAt 255 textstring
         in putByteStringWithLength h <> if BS.null t
                then mempty
                else putTXT t
    putSRV priority weight port target = mconcat
        [ put16 priority
        , put16 weight
        , put16 port
        , putDomain target
        ]
    putDS keytag keyalg digestType digest = mconcat
        [ put16 keytag
        , put8 keyalg
        , put8 digestType
        , putByteString digest
        ]
    putRRSIG RDREP_RRSIG{..} = mconcat
        [ put16 $ fromTYPE rrsigType
        , put8 rrsigKeyAlg
        , put8 rrsigNumLabels
        , put32 rrsigTTL
        , put32 $ fromIntegral rrsigExpiration
        , put32 $ fromIntegral rrsigInception
        , put16 rrsigKeyTag
        , putDomain rrsigZone
        , putByteString rrsigValue
        ]
    putDNSKEY flags protocol alg key = mconcat
        [ put16 flags
        , put8 protocol
        , put8 alg
        , putByteString key
        ]
    putNSEC3 alg flags iterations salt hash types = mconcat
        [ put8 alg
        , put8 flags
        , put16 iterations
        , putByteStringWithLength salt
        , putByteStringWithLength hash
        , putNsecTypes types
        ]
    putNSEC3PARAM alg flags iterations salt = mconcat
        [ put8 alg
        , put8 flags
        , put16 iterations
        , putByteStringWithLength salt
        ]
    putTLSA usage selector mtype assocData = mconcat
        [ put8 usage
        , put8 selector
        , put8 mtype
        , putByteString assocData
        ]
    putCAA flags tag value = mconcat
        [ put8 flags
        , putByteStringWithLength tag
        , putByteString value
        ]

-- | Encode DNSSEC NSEC type bits
putNsecTypes :: [TYPE] -> SPut
putNsecTypes types = putTypeList $ map fromTYPE types
  where
    putTypeList :: [Word16] -> SPut
    putTypeList ts =
        mconcat [ putWindow (the top8) bot8 |
                  t <- ts,
                  let top8 = fromIntegral t `shiftR` 8,
                  let bot8 = fromIntegral t .&. 0xff,
                  then group by top8
                       using groupWith ]

    putWindow :: Int -> [Int] -> SPut
    putWindow top8 bot8s =
        let blks = maximum bot8s `shiftR` 3
         in putInt8 top8
            <> put8 (1 + fromIntegral blks)
            <> putBits 0 [ (the block, foldl' mergeBits 0 bot8) |
                           bot8 <- bot8s,
                           let block = bot8 `shiftR` 3,
                           then group by block
                                using groupWith ]
      where
        -- | Combine type bits in network bit order, i.e. bit 0 first.
        mergeBits acc b = setBit acc (7 - b.&.0x07)

    putBits :: Int -> [(Int, Word8)] -> SPut
    putBits _ [] = pure mempty
    putBits n ((block, octet) : rest) =
        putReplicate (block-n) 0
        <> put8 octet
        <> putBits (block + 1) rest

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
            Nothing  -> do
                        -- Pointers are limited to 14-bits!
                        when (cur <= 0x3fff) $ wsPush dom cur
                        mconcat [ putPartialDomain hd
                                , putDomain' '.' tl
                                ]
  where
    -- Try with the preferred separator if present, else fall back to '.'.
    (hd, tl) = loop (c2w sep)
      where
        loop w = case parseLabel w dom of
            Right p | w /= 0x2e && BS.null (snd p) -> loop 0x2e
                    | otherwise -> p
            Left e -> E.throw e

    c2w = fromIntegral . fromEnum

putPointer :: Int -> SPut
putPointer pos = putInt16 (pos .|. 0xc000)

putPartialDomain :: Domain -> SPut
putPartialDomain = putByteStringWithLength
