{-# LANGUAGE PatternSynonyms #-}

module Network.DNS.Types.EDNS (
    EDNS(..)
  , defaultEDNS
  , maxUdpSize
  , minUdpSize
  , OptCode (
    NSID
  , DAU
  , DHU
  , N3U
  , ClientSubnet
  )
  , fromOptCode
  , toOptCode
  , odataToOptCode
  , OData(..)
  , putOData
  , getOData
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as S8
import Data.IP (IP(..), fromIPv4, toIPv4, fromIPv6b, toIPv6b, makeAddrRange)
import qualified Data.IP (addr)

import Network.DNS.Imports
import Network.DNS.StateBinary
import Network.DNS.Types.Base

----------------------------------------------------------------
-- EDNS (RFC 6891, EDNS(0))
----------------------------------------------------------------

-- | EDNS information defined in RFC 6891.
data EDNS = EDNS {
    -- | EDNS version, presently only version 0 is defined.
    ednsVersion :: !Word8
    -- | Supported UDP payload size.
  , ednsUdpSize  :: !Word16
    -- | Request DNSSEC replies (with RRSIG and NSEC records as as appropriate)
    -- from the server.  Generally, not needed (except for diagnostic purposes)
    -- unless the signatures will be validated.  Just setting the 'AD' bit in
    -- the query and checking it in the response is sufficient (but often
    -- subject to man-in-the-middle forgery) if all that's wanted is whether
    -- the server validated the response.
  , ednsDnssecOk :: !Bool
    -- | EDNS options (e.g. 'OD_NSID', 'OD_ClientSubnet', ...)
  , ednsOptions  :: ![OData]
  } deriving (Eq, Show)

-- | The default EDNS pseudo-header for queries.  The UDP buffer size is set to
--   1216 bytes, which should result in replies that fit into the 1280 byte
--   IPv6 minimum MTU.  Since IPv6 only supports fragmentation at the source,
--   and even then not all gateways forward IPv6 pre-fragmented IPv6 packets,
--   it is best to keep DNS packet sizes below this limit when using IPv6
--   nameservers.  A larger value may be practical when using IPv4 exclusively.
--
-- @
-- defaultEDNS = EDNS
--     { ednsVersion = 0      -- The default EDNS version is 0
--     , ednsUdpSize = 1232   -- IPv6-safe UDP MTU (RIPE recommendation)
--     , ednsDnssecOk = False -- We don't do DNSSEC validation
--     , ednsOptions = []     -- No EDNS options by default
--     }
-- @
--
defaultEDNS :: EDNS
defaultEDNS = EDNS
    { ednsVersion = 0      -- The default EDNS version is 0
    , ednsUdpSize = 1232   -- IPv6-safe UDP MTU
    , ednsDnssecOk = False -- We don't do DNSSEC validation
    , ednsOptions = []     -- No EDNS options by default
    }

-- | Maximum UDP size that can be advertised.  If the 'ednsUdpSize' of 'EDNS'
--   is larger, then this value is sent instead.  This value is likely to work
--   only for local nameservers on the loopback network.  Servers may enforce
--   a smaller limit.
--
-- >>> maxUdpSize
-- 16384
maxUdpSize :: Word16
maxUdpSize = 16384

-- | Minimum UDP size to advertise. If 'ednsUdpSize' of 'EDNS' is smaller,
--   then this value is sent instead.
--
-- >>> minUdpSize
-- 512
minUdpSize :: Word16
minUdpSize = 512

----------------------------------------------------------------

-- | EDNS Option Code (RFC 6891).
newtype OptCode = OptCode {
    -- | From option code to number.
    fromOptCode :: Word16
  } deriving (Eq,Ord)

-- | NSID (RFC5001, section 2.3)
pattern NSID :: OptCode
pattern NSID  = OptCode 3

-- | DNSSEC algorithm support (RFC6974, section 3)
pattern DAU  :: OptCode
pattern DAU   = OptCode 5
pattern DHU  :: OptCode
pattern DHU   = OptCode 6
pattern N3U  :: OptCode
pattern N3U   = OptCode 7

-- | Client subnet (RFC7871)
pattern ClientSubnet :: OptCode
pattern ClientSubnet = OptCode 8

instance Show OptCode where
    show NSID         = "NSID"
    show DAU          = "DAU"
    show DHU          = "DHU"
    show N3U          = "N3U"
    show ClientSubnet = "ClientSubnet"
    show x            = "OptCode" ++ show (fromOptCode x)

-- | From number to option code.
toOptCode :: Word16 -> OptCode
toOptCode = OptCode

----------------------------------------------------------------

-- | RData formats for a few EDNS options, and an opaque catchall
data OData =
      -- | Name Server Identifier (RFC5001).  Bidirectional, empty from client.
      -- (opaque octet-string).  May contain binary data, which MUST be empty
      -- in queries.
      OD_NSID ByteString
      -- | DNSSEC Algorithm Understood (RFC6975).  Client to server.
      -- (array of 8-bit numbers). Lists supported DNSKEY algorithms.
    | OD_DAU [Word8]
      -- | DS Hash Understood (RFC6975).  Client to server.
      -- (array of 8-bit numbers). Lists supported DS hash algorithms.
    | OD_DHU [Word8]
      -- | NSEC3 Hash Understood (RFC6975).  Client to server.
      -- (array of 8-bit numbers). Lists supported NSEC3 hash algorithms.
    | OD_N3U [Word8]
      -- | Client subnet (RFC7871).  Bidirectional.
      -- (source bits, scope bits, address).
      -- The address is masked and truncated when encoding queries.  The
      -- address is zero-padded when decoding.  Invalid input encodings
      -- result in an 'OD_ECSgeneric' value instead.
      --
    | OD_ClientSubnet Word8 Word8 IP
      -- | Unsupported or malformed IP client subnet option.  Bidirectional.
      -- (address family, source bits, scope bits, opaque address).
    | OD_ECSgeneric Word16 Word8 Word8 ByteString
      -- | Generic EDNS option.
      -- (numeric 'OptCode', opaque content)
    | UnknownOData Word16 ByteString
    deriving (Eq,Ord)


-- | Recover the (often implicit) 'OptCode' from a value of the 'OData' sum
-- type.
odataToOptCode :: OData -> OptCode
odataToOptCode OD_NSID {}            = NSID
odataToOptCode OD_DAU {}             = DAU
odataToOptCode OD_DHU {}             = DHU
odataToOptCode OD_N3U {}             = N3U
odataToOptCode OD_ClientSubnet {}    = ClientSubnet
odataToOptCode OD_ECSgeneric {}      = ClientSubnet
odataToOptCode (UnknownOData code _) = toOptCode code

instance Show OData where
    show (OD_NSID nsid) = _showNSID nsid
    show (OD_DAU as)    = _showAlgList "DAU" as
    show (OD_DHU hs)    = _showAlgList "DHU" hs
    show (OD_N3U hs)    = _showAlgList "N3U" hs
    show (OD_ClientSubnet b1 b2 ip@(IPv4 _)) = _showECS 1 b1 b2 $ show ip
    show (OD_ClientSubnet b1 b2 ip@(IPv6 _)) = _showECS 2 b1 b2 $ show ip
    show (OD_ECSgeneric fam b1 b2 a) = _showECS fam b1 b2 $ _b16encode a
    show (UnknownOData code bs) =
        "UnknownOData " ++ show code ++ " " ++ _b16encode bs

_showAlgList :: String -> [Word8] -> String
_showAlgList nm ws = nm ++ " " ++ intercalate "," (map show ws)

_showNSID :: ByteString -> String
_showNSID nsid = "NSID" ++ " " ++ _b16encode nsid ++ ";" ++ printable nsid
  where
    printable = S8.unpack. S8.map (\c -> if c < ' ' || c > '~' then '?' else c)

_showECS :: Word16 -> Word8 -> Word8 -> String -> String
_showECS family srcBits scpBits address =
    show family ++ " " ++ show srcBits
                ++ " " ++ show scpBits ++ " " ++ address

----------------------------------------------------------------

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
            , putInt16 $ 4 + S8.length addr
            , put16 family
            , put8 srcBits
            , put8 scpBits
            , putByteString addr
            ]
putOData (UnknownOData code bs) = putODBytes code bs

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
            , putInt16 $ S8.length bs
            , putByteString bs
            ]

----------------------------------------------------------------

getOData :: OptCode -> Int -> SGet OData
getOData NSID len = OD_NSID <$> getNByteString len
getOData DAU  len = OD_DAU  <$> getNoctets len
getOData DHU  len = OD_DHU  <$> getNoctets len
getOData N3U  len = OD_N3U  <$> getNoctets len
getOData ClientSubnet len = do
        family  <- get16
        srcBits <- get8
        scpBits <- get8
        addrbs  <- getNByteString (len - 4) -- 4 = 2 + 1 + 1
        --
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
        -- In order to avoid needless decoding errors, when the ECS encoding
        -- requirements are violated, we construct an OD_ECSgeneric OData,
        -- instread of an IP-specific OD_ClientSubnet OData, which will only
        -- be used for valid inputs.  When the family is neither IPv4(1) nor
        -- IPv6(2), or the address prefix is not correctly encoded (too long
        -- or too short), the OD_ECSgeneric data contains the verbatim input
        -- from the peer.
        --
        case S8.length addrbs == (fromIntegral srcBits + 7) `div` 8 of
            True | Just ip <- bstoip family addrbs srcBits scpBits
                -> pure $ OD_ClientSubnet srcBits scpBits ip
            _   -> pure $ OD_ECSgeneric family srcBits scpBits addrbs
  where
    prefix addr bits = Data.IP.addr $ makeAddrRange addr $ fromIntegral bits
    zeropad = (++ repeat 0). map fromIntegral. BS.unpack
    checkBits fromBytes toIP srcBits scpBits bytes =
        let addr       = fromBytes bytes
            maskedAddr = prefix addr srcBits
            maxBits    = fromIntegral $ 8 * length bytes
         in if addr == maskedAddr && scpBits <= maxBits
            then Just $ toIP addr
            else Nothing
    bstoip :: Word16 -> BS.ByteString -> Word8 -> Word8 -> Maybe IP
    bstoip family bs srcBits scpBits = case family of
        1 -> checkBits toIPv4  IPv4 srcBits scpBits $ take 4  $ zeropad bs
        2 -> checkBits toIPv6b IPv6 srcBits scpBits $ take 16 $ zeropad bs
        _ -> Nothing
getOData opc len = UnknownOData (fromOptCode opc) <$> getNByteString len
