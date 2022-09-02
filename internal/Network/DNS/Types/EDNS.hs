{-# LANGUAGE PatternSynonyms #-}

module Network.DNS.Types.EDNS where

import qualified Data.ByteString.Char8 as BS
import Data.IP (IP(..))

import Network.DNS.Imports
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
pattern NSID = OptCode 3

-- | DNSSEC algorithm support (RFC6974, section 3)
pattern DAU :: OptCode
pattern DAU = OptCode 5
pattern DHU :: OptCode
pattern DHU = OptCode 6
pattern N3U :: OptCode
pattern N3U = OptCode 7

-- | Client subnet (RFC7871)
pattern ClientSubnet :: OptCode
pattern ClientSubnet = OptCode 8

instance Show OptCode where
    show NSID         = "NSID"
    show DAU          = "DAU"
    show DHU          = "DHU"
    show N3U          = "N3U"
    show ClientSubnet = "ClientSubnet"
    show x            = "OptCode" ++ (show $ fromOptCode x)

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
_odataToOptCode :: OData -> OptCode
_odataToOptCode OD_NSID {}            = NSID
_odataToOptCode OD_DAU {}             = DAU
_odataToOptCode OD_DHU {}             = DHU
_odataToOptCode OD_N3U {}             = N3U
_odataToOptCode OD_ClientSubnet {}    = ClientSubnet
_odataToOptCode OD_ECSgeneric {}      = ClientSubnet
_odataToOptCode (UnknownOData code _) = toOptCode code

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
    printable = BS.unpack. BS.map (\c -> if c < ' ' || c > '~' then '?' else c)

_showECS :: Word16 -> Word8 -> Word8 -> String -> String
_showECS family srcBits scpBits address =
    show family ++ " " ++ show srcBits
                ++ " " ++ show scpBits ++ " " ++ address
