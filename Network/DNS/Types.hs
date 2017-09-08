{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Data types for DNS Query and Response.
--   For more information, see <http://www.ietf.org/rfc/rfc1035>.

module Network.DNS.Types (
  -- * Resource Records
    ResourceRecord (..)
  -- ** Types
  , Domain
  , CLASS
  , classIN
  , TTL
  -- ** Resource Record Types
  , TYPE (
    A
  , NS
  , CNAME
  , SOA
  , NULL
  , PTR
  , MX
  , TXT
  , AAAA
  , SRV
  , DNAME
  , OPT
  , DS
  , RRSIG
  , NSEC
  , DNSKEY
  , NSEC3
  , NSEC3PARAM
  , TLSA
  , CDS
  , CDNSKEY
  , CSYNC
  , ANY
  )
  , toTYPE
  , fromTYPE
  , typeToInt
  , intToType
  -- ** Resource Data
  , RData (..)
  -- * DNS Message
  , DNSMessage (..)
  , defaultQuery
  , defaultResponse
  , DNSFormat
  -- ** DNS Header
  , DNSHeader (..)
  , Identifier
  , QorR (..)
  , DNSFlags (..)
  , OPCODE (..)
  , RCODE (
    NoErr
  , FormatErr
  , ServFail
  , NameErr
  , NotImpl
  , Refused
  , BadOpt
  )
  , toRCODE
  , fromRCODE
  , toRCODEforHeader
  , fromRCODEforHeader
  -- ** DNS Body
  , Question (..)
  -- * DNS Error
  , DNSError (..)
  -- * EDNS0
  , EDNS0
  , udpSize
  , extRCODE
  , dnssecOk
  , options
  , defaultEDNS0
  , fromEDNS0
  , toEDNS0
  -- * EDNS0 option data
  , OData (..)
  , OptCode (
    ClientSubnet
  )
  , toOptCode
  , fromOptCode
  -- * Other types
  , Mailbox
  ) where

import Control.Exception (Exception)
import Data.Bits ((.&.), (.|.), shiftR, shiftL, testBit, setBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as B64 (encode)
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Builder as L
import qualified Data.ByteString.Lazy as L
import Data.IP (IP, IPv4, IPv6)
import Data.Typeable (Typeable)
import Data.Word (Word8, Word16, Word32)

----------------------------------------------------------------

-- | Type for domain.
type Domain = ByteString

-- | Type for a mailbox encoded on the wire as a DNS name, but the first label
-- is conceptually the user name, and sometimes has internal '.' characters
-- that are not label separators.
type Mailbox = ByteString

----------------------------------------------------------------

-- | Types for resource records.
newtype TYPE = TYPE {
    -- | From type to number.
    fromTYPE :: Word16
  } deriving Eq

-- https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4

-- | IPv4 address
pattern A :: TYPE
pattern A          = TYPE   1
-- | An authoritative name serve
pattern NS :: TYPE
pattern NS         = TYPE   2
-- | The canonical name for an alias
pattern CNAME :: TYPE
pattern CNAME      = TYPE   5
-- | Marks the start of a zone of authority
pattern SOA :: TYPE
pattern SOA        = TYPE   6
-- | A null RR (EXPERIMENTAL)
pattern NULL :: TYPE
pattern NULL       = TYPE  10
-- | A domain name pointer
pattern PTR :: TYPE
pattern PTR        = TYPE  12
-- | Mail exchange
pattern MX :: TYPE
pattern MX         = TYPE  15
-- | Text strings
pattern TXT :: TYPE
pattern TXT        = TYPE  16
-- | IPv6 Address
pattern AAAA :: TYPE
pattern AAAA       = TYPE  28
-- | Server Selection (RFC2782)
pattern SRV :: TYPE
pattern SRV        = TYPE  33
-- | DNAME (RFC6672)
pattern DNAME :: TYPE
pattern DNAME      = TYPE  39 -- RFC 6672
-- | OPT (RFC6891)
pattern OPT :: TYPE
pattern OPT        = TYPE  41 -- RFC 6891
-- | Delegation Signer (RFC4034)
pattern DS :: TYPE
pattern DS         = TYPE  43 -- RFC 4034
-- | RRSIG (RFC4034)
pattern RRSIG :: TYPE
pattern RRSIG      = TYPE  46 -- RFC 4034
-- | NSEC (RFC4034)
pattern NSEC :: TYPE
pattern NSEC       = TYPE  47 -- RFC 4034
-- | DNSKEY (RFC4034)
pattern DNSKEY :: TYPE
pattern DNSKEY     = TYPE  48 -- RFC 4034
-- | NSEC3 (RFC5155)
pattern NSEC3 :: TYPE
pattern NSEC3      = TYPE  50 -- RFC 5155
-- | NSEC3PARAM (RFC5155)
pattern NSEC3PARAM :: TYPE
pattern NSEC3PARAM = TYPE  51 -- RFC 5155
-- | TLSA (RFC6698)
pattern TLSA :: TYPE
pattern TLSA       = TYPE  52 -- RFC 6698
-- | Child DS (RFC7344)
pattern CDS :: TYPE
pattern CDS        = TYPE  59 -- RFC 7344
-- | DNSKEY(s) the Child wants reflected in DS (RFC7344)
pattern CDNSKEY :: TYPE
pattern CDNSKEY    = TYPE  60 -- RFC 7344
-- | Child-To-Parent Synchronization (RFC7477)
pattern CSYNC :: TYPE
pattern CSYNC      = TYPE  62 -- RFC 7477
-- | A request for all records the server/cache has available
pattern ANY :: TYPE
pattern ANY        = TYPE 255

instance Show TYPE where
    show A          = "A"
    show NS         = "NS"
    show CNAME      = "CNAME"
    show SOA        = "SOA"
    show NULL       = "NULL"
    show PTR        = "PTR"
    show MX         = "MX"
    show TXT        = "TXT"
    show AAAA       = "AAAA"
    show SRV        = "SRV"
    show DNAME      = "DNAME"
    show OPT        = "OPT"
    show DS         = "DS"
    show RRSIG      = "RRSIG"
    show NSEC       = "NSEC"
    show DNSKEY     = "DNSKEY"
    show NSEC3      = "NSEC3"
    show NSEC3PARAM = "NSEC3PARAM"
    show TLSA       = "TLSA"
    show CDS        = "CDS"
    show CDNSKEY    = "CDNSKEY"
    show CSYNC      = "CSYNC"
    show ANY        = "ANY"
    show x          = "TYPE " ++ (show $ typeToInt x)

-- | From number to type.
toTYPE :: Word16 -> TYPE
toTYPE = TYPE

{-# DEPRECATED intToType "Use toTYPE instead." #-}
-- | From number to type. Naming is for historical reasons.
intToType :: Word16 -> TYPE
intToType = TYPE

{-# DEPRECATED typeToInt "Use fromTYPE instead." #-}
-- | From type to number. Naming is for historical reasons.
typeToInt :: TYPE -> Word16
typeToInt = fromTYPE

----------------------------------------------------------------

-- | An enumeration of all possible DNS errors that can occur.
data DNSError =
    -- | The sequence number of the answer doesn't match our query. This
    --   could indicate foul play.
    SequenceNumberMismatch
    -- | The number of retries for the request was exceeded.
  | RetryLimitExceeded
    -- | The request simply timed out.
  | TimeoutExpired
    -- | The answer has the correct sequence number, but returned an
    --   unexpected RDATA format.
  | UnexpectedRDATA
    -- | The domain for query is illegal.
  | IllegalDomain
    -- | The name server was unable to interpret the query.
  | FormatError
    -- | The name server was unable to process this query due to a
    --   problem with the name server.
  | ServerFailure
    -- | This code signifies that the domain name referenced in the
    --   query does not exist.
  | NameError
    -- | The name server does not support the requested kind of query.
  | NotImplemented
    -- | The name server refuses to perform the specified operation for
    --   policy reasons.  For example, a name
    --   server may not wish to provide the
    --   information to the particular requester,
    --   or a name server may not wish to perform
    --   a particular operation (e.g., zone transfer) for particular data.
  | OperationRefused
    -- | The server detected a malformed OPT RR.
  | BadOptRecord
    -- | Configuration is wrong.
  | BadConfiguration
    -- | Error is unkown
  | UnknownError
  deriving (Eq, Show, Typeable)

instance Exception DNSError

-- | Raw data format for DNS Query and Response.
data DNSMessage = DNSMessage {
    header     :: DNSHeader        -- ^ Header
  , question   :: [Question]       -- ^ The question for the name server
  , answer     :: [ResourceRecord] -- ^ RRs answering the question
  , authority  :: [ResourceRecord] -- ^ RRs pointing toward an authority
  , additional :: [ResourceRecord] -- ^ RRs holding additional information
  } deriving (Eq, Show)

{-# DEPRECATED DNSFormat "Use DNSMessage instead" #-}
-- | For backward compatibility.
type DNSFormat = DNSMessage

-- | An identifier assigned by the program that
--   generates any kind of query.
type Identifier = Word16

-- | Raw data format for the header of DNS Query and Response.
data DNSHeader = DNSHeader {
    identifier :: Identifier -- ^ An identifier.
  , flags      :: DNSFlags   -- ^ The second 16bit word.
  } deriving (Eq, Show)

-- | Raw data format for the flags of DNS Query and Response.
data DNSFlags = DNSFlags {
    qOrR         :: QorR   -- ^ Query or response.
  , opcode       :: OPCODE -- ^ Kind of query.
  , authAnswer   :: Bool   -- ^ Authoritative Answer - this bit is valid in responses,
                           -- and specifies that the responding name server is an
                           -- authority for the domain name in question section.
  , trunCation   :: Bool   -- ^ TrunCation - specifies that this message was truncated
                           -- due to length greater than that permitted on the
                           -- transmission channel.
  , recDesired   :: Bool   -- ^ Recursion Desired - this bit may be set in a query and
                           -- is copied into the response.  If RD is set, it directs
                           -- the name server to pursue the query recursively.
                           -- Recursive query support is optional.
  , recAvailable :: Bool   -- ^ Recursion Available - this be is set or cleared in a
                           -- response, and denotes whether recursive query support is
                           -- available in the name server.

  , rcode        :: RCODE  -- ^ Response code.
  , authenData   :: Bool   -- ^ Authentic Data (RFC4035).
  } deriving (Eq, Show)

----------------------------------------------------------------

-- | Query or response.
data QorR = QR_Query    -- ^ Query.
          | QR_Response -- ^ Response.
          deriving (Eq, Show, Enum, Bounded)

-- | Kind of query.
data OPCODE
  = OP_STD -- ^ A standard query.
  | OP_INV -- ^ An inverse query.
  | OP_SSR -- ^ A server status request.
  deriving (Eq, Show, Enum, Bounded)

----------------------------------------------------------------

-- | Response code including EDNS0's 12bit ones.
newtype RCODE = RCODE {
    -- | From rcode to number.
    fromRCODE :: Word16
  } deriving (Eq)

-- | No error condition.
pattern NoErr     :: RCODE
pattern NoErr      = RCODE  0
-- | Format error - The name server was
--   unable to interpret the query.
pattern FormatErr :: RCODE
pattern FormatErr  = RCODE  1
-- | Server failure - The name server was
--   unable to process this query due to a
--   problem with the name server.
pattern ServFail  :: RCODE
pattern ServFail   = RCODE  2
-- | Name Error - Meaningful only for
--   responses from an authoritative name
--   server, this code signifies that the
--   domain name referenced in the query does
--   not exist.
pattern NameErr   :: RCODE
pattern NameErr    = RCODE  3
-- | Not Implemented - The name server does
--   not support the requested kind of query.
pattern NotImpl   :: RCODE
pattern NotImpl    = RCODE  4
-- | Refused - The name server refuses to
--   perform the specified operation for
--   policy reasons.  For example, a name
--   server may not wish to provide the
--   information to the particular requester,
--   or a name server may not wish to perform
--   a particular operation (e.g., zone
--   transfer) for particular data.
pattern Refused   :: RCODE
pattern Refused    = RCODE  5
-- | Bad OPT Version (RFC 6891) or TSIG Signature Failure (RFC2845).
pattern BadOpt    :: RCODE
pattern BadOpt     = RCODE 16

instance Show RCODE where
    show NoErr     = "NoErr"
    show FormatErr = "Format"
    show ServFail  = "ServFail"
    show NameErr   = "NameErr"
    show NotImpl   = "NotImpl"
    show Refused   = "Refused"
    show BadOpt    = "BadOpt"
    show x         = "RCODE " ++ (show $ fromRCODE x)

-- | From number to rcode.
toRCODE :: Word16 -> RCODE
toRCODE = RCODE

-- | From rcode to number for header (4bits only).
fromRCODEforHeader :: RCODE -> Word16
fromRCODEforHeader (RCODE w) = w .&. 0x0f

-- | From number in header to rcode (4bits only).
toRCODEforHeader :: Word16 -> RCODE
toRCODEforHeader w = RCODE (w .&. 0x0f)

----------------------------------------------------------------

-- | Raw data format for DNS questions.
data Question = Question {
    qname  :: Domain -- ^ A domain name
  , qtype  :: TYPE   -- ^ The type of the query
  } deriving (Eq, Show)

----------------------------------------------------------------

-- | Resource record class.
type CLASS = Word16

-- | Resource record class for the Internet.
classIN :: CLASS
classIN = 1

-- | Time to live.
type TTL = Word32

-- | Raw data format for resource records.
data ResourceRecord = ResourceRecord {
    rrname  :: Domain -- ^ Name
  , rrtype  :: TYPE   -- ^ Resource record type
  , rrclass :: CLASS  -- ^ Resource record class
  , rrttl   :: TTL    -- ^ Time to live
  , rdata   :: RData  -- ^ Resource data
  } deriving (Eq,Show)

-- | Raw data format for each type.
data RData = RD_A IPv4           -- ^ IPv4 address
           | RD_NS Domain        -- ^ An authoritative name serve
           | RD_CNAME Domain     -- ^ The canonical name for an alias
           | RD_SOA Domain Mailbox Word32 Word32 Word32 Word32 Word32
                                 -- ^ Marks the start of a zone of authority
           | RD_NULL             -- ^ A null RR (EXPERIMENTAL).
                                 -- Anything can be in a NULL record,
                                 -- for now we just drop this data.
           | RD_PTR Domain       -- ^ A domain name pointer
           | RD_MX Word16 Domain -- ^ Mail exchange
           | RD_TXT ByteString   -- ^ Text strings
           | RD_AAAA IPv6        -- ^ IPv6 Address
           | RD_SRV Word16 Word16 Word16 Domain
                                 -- ^ Server Selection (RFC2782)
           | RD_DNAME Domain     -- ^ DNAME (RFC6672)
           | RD_OPT [OData]      -- ^ OPT (RFC6891)
           | RD_DS Word16 Word8 Word8 ByteString -- ^ Delegation Signer (RFC4034)
           --RD_RRSIG
           --RD_NSEC
           | RD_DNSKEY Word16 Word8 Word8 ByteString
                                 -- ^ DNSKEY (RFC4034)
           --RD_NSEC3
           --RD_NSEC3PARAM
           | RD_TLSA Word8 Word8 Word8 ByteString
                                 -- ^ TLSA (RFC6698)
           --RD_CDS
           --RD_CDNSKEY
           --RD_CSYNC
           | RD_OTH ByteString   -- ^ Unknown resource data
    deriving (Eq, Ord)

instance Show RData where
  show (RD_NS dom) = BS.unpack dom
  show (RD_MX prf dom) = show prf ++ " " ++ BS.unpack dom
  show (RD_CNAME dom) = BS.unpack dom
  show (RD_DNAME dom) = BS.unpack dom
  show (RD_A a) = show a
  show (RD_AAAA aaaa) = show aaaa
  show (RD_TXT txt) = BS.unpack txt
  show (RD_SOA mn mr serial refresh retry expire mi) = BS.unpack mn ++ " " ++ BS.unpack mr ++ " " ++
                                                       show serial ++ " " ++ show refresh ++ " " ++
                                                       show retry ++ " " ++ show expire ++ " " ++ show mi
  show (RD_PTR dom) = BS.unpack dom
  show (RD_SRV pri wei prt dom) = show pri ++ " " ++ show wei ++ " " ++ show prt ++ BS.unpack dom
  show (RD_OPT od) = show od
  show (RD_OTH is) = show is
  show (RD_TLSA use sel mtype dgst) = show use ++ " " ++ show sel ++ " " ++ show mtype ++ " " ++ hexencode dgst
  show (RD_DS t a dt dv) = show t ++ " " ++ show a ++ " " ++ show dt ++ " " ++ hexencode dv
  show RD_NULL = "NULL"
  show (RD_DNSKEY f p a k) = show f ++ " " ++ show p ++ " " ++ show a ++ " " ++ b64encode k

hexencode :: ByteString -> String
hexencode = BS.unpack . L.toStrict . L.toLazyByteString . L.byteStringHex

b64encode :: ByteString -> String
b64encode = BS.unpack . B64.encode

----------------------------------------------------------------

-- | Default query.
defaultQuery :: DNSMessage
defaultQuery = DNSMessage {
    header = DNSHeader {
       identifier = 0
     , flags = DNSFlags {
           qOrR         = QR_Query
         , opcode       = OP_STD
         , authAnswer   = False
         , trunCation   = False
         , recDesired   = True
         , recAvailable = False
         , rcode        = NoErr
         , authenData   = False
         }
     }
  , question   = []
  , answer     = []
  , authority  = []
  , additional = []
  }

-- | Default response.
defaultResponse :: DNSMessage
defaultResponse =
  let hd = header defaultQuery
      flg = flags hd
  in  defaultQuery {
        header = hd {
          flags = flg {
              qOrR = QR_Response
            , authAnswer = True
            , recAvailable = True
            , authenData = False
            }
        }
      }

----------------------------------------------------------------
-- EDNS0 (RFC 6891)
----------------------------------------------------------------

-- | EDNS0 infromation defined in RFC 6891.
data EDNS0 = EDNS0 {
    -- | UDP payload size.
    udpSize  :: Word16
    -- | Extended RCODE.
  , extRCODE :: RCODE
    -- | Is DNSSEC OK?
  , dnssecOk :: Bool
    -- | EDNS0 option data.
  , options  :: [OData]
  } deriving (Eq, Show)

-- | Default information for EDNS0.
defaultEDNS0 :: EDNS0
defaultEDNS0 = EDNS0 4096 NoErr False []

-- | Generating a resource record for the additional section based on EDNS0.
-- 'DNSFlags' is not generated.
-- Just set the same 'RCODE' to 'DNSFlags'.
fromEDNS0 :: EDNS0 -> ResourceRecord
fromEDNS0 edns = ResourceRecord name' type' class' ttl' rdata'
  where
    name'  = "."
    type'  = OPT
    class' = udpSize edns
    ttl0'   = fromIntegral (fromRCODE (extRCODE edns) .&. 0x0ff0) `shiftL` 20
    ttl'
      | dnssecOk edns = ttl0' `setBit` 15
      | otherwise     = ttl0'
    rdata' = RD_OPT $ options edns

-- | Generating EDNS0 information from the OPT RR.
toEDNS0 :: DNSFlags -> ResourceRecord -> Maybe EDNS0
toEDNS0 flgs (ResourceRecord "." OPT udpsiz ttl' (RD_OPT opts)) =
    Just $ EDNS0 udpsiz (toRCODE erc) secok opts
  where
    lp = fromRCODEforHeader $ rcode flgs
    up = shiftR (ttl' .&. 0xff000000) 20
    erc = fromIntegral up .|. lp
    secok = ttl' `testBit` 15
toEDNS0 _ _ = Nothing

----------------------------------------------------------------

-- | EDNS0 Option Code (RFC 6891).
newtype OptCode = OptCode {
    -- | From option code to number.
    fromOptCode :: Word16
  } deriving (Eq,Ord)

-- | Client subnet (RFC7871)
pattern ClientSubnet :: OptCode
pattern ClientSubnet = OptCode 8

instance Show OptCode where
    show ClientSubnet = "ClientSubnet"
    show x            = "OptCode " ++ (show $ fromOptCode x)

-- | From number to option code.
toOptCode :: Word16 -> OptCode
toOptCode = OptCode

----------------------------------------------------------------

-- | Optional resource data.
data OData = OD_ClientSubnet Word8 Word8 IP -- ^ Client subnet (RFC7871)
           | OD_Unknown OptCode ByteString  -- ^ Unknown optional type
    deriving (Eq,Show,Ord)
