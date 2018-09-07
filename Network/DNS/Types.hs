{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE CPP #-}

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
  , fromTYPE
  , toTYPE
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
  -- *** DNS flags
  , DNSFlags (..)
  , QorR (..)
  , defaultDNSFlags
  -- *** Query flags
  , FlagOp(..)
  , QueryFlags
  , rdFlag
  , adFlag
  , cdFlag
  , queryDNSFlags
  -- **** OPCODE and RCODE
  , OPCODE (..)
  , fromOPCODE
  , toOPCODE
  , RCODE (
    NoErr
  , FormatErr
  , ServFail
  , NameErr
  , NotImpl
  , Refused
  , YXDomain
  , YXRRSet
  , NXRRSet
  , NotAuth
  , NotZone
  , BadOpt
  )
  , fromRCODE
  , toRCODE
  , fromRCODEforHeader
  , toRCODEforHeader
  -- ** DNS Body
  , Question (..)
  -- * DNS Error
  , DNSError (..)
  -- * EDNS0
  , EDNS0
  , defaultEDNS0
  , maxUdpSize
  , minUdpSize
  -- ** Accessors
  , udpSize
  , extRCODE
  , dnssecOk
  , options
  -- ** Converters
  , fromEDNS0
  , toEDNS0
  -- * EDNS0 option data
  , OData (..)
  , OptCode (
    ClientSubnet
  )
  , fromOptCode
  , toOptCode
  -- * Other types
  , Mailbox
  ) where

import Control.Exception (Exception, IOException)
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Builder as L
import qualified Data.ByteString.Lazy as L
import Data.IP (IP, IPv4, IPv6)
import qualified Data.List as List
import qualified Data.Semigroup as Sem

import Network.DNS.Imports

----------------------------------------------------------------

-- | Type for domain.
type Domain = ByteString

-- | Type for a mailbox encoded on the wire as a DNS name, but the first label
-- is conceptually the user name, and sometimes has contains internal periods
-- that are not label separators. Therefore, in mailboxes \@ is used as the
-- separator between the first and second labels.
type Mailbox = ByteString

----------------------------------------------------------------

#if __GLASGOW_HASKELL__ >= 802
-- | Types for resource records.
newtype TYPE = TYPE {
    -- | From type to number.
    fromTYPE :: Word16
  } deriving (Eq, Ord)

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
    show x          = "TYPE " ++ (show $ fromTYPE x)

-- | From number to type.
toTYPE :: Word16 -> TYPE
toTYPE = TYPE
#else
-- | Types for resource records.
data TYPE = A          -- ^ IPv4 address
          | NS         -- ^ An authoritative name serve
          | CNAME      -- ^ The canonical name for an alias
          | SOA        -- ^ Marks the start of a zone of authority
          | NULL       -- ^ A null RR (EXPERIMENTAL)
          | PTR        -- ^ A domain name pointer
          | MX         -- ^ Mail exchange
          | TXT        -- ^ Text strings
          | AAAA       -- ^ IPv6 Address
          | SRV        -- ^ Server Selection (RFC2782)
          | DNAME      -- ^ DNAME (RFC6672)
          | OPT        -- ^ OPT (RFC6891)
          | DS         -- ^ Delegation Signer (RFC4034)
          | RRSIG      -- ^ RRSIG (RFC4034)
          | NSEC       -- ^ NSEC (RFC4034)
          | DNSKEY     -- ^ DNSKEY (RFC4034)
          | NSEC3      -- ^ NSEC3 (RFC5155)
          | NSEC3PARAM -- ^ NSEC3PARAM (RFC5155)
          | TLSA       -- ^ TLSA (RFC6698)
          | CDS        -- ^ Child DS (RFC7344)
          | CDNSKEY    -- ^ DNSKEY(s) the Child wants reflected in DS (RFC7344)
          | CSYNC      -- ^ Child-To-Parent Synchronization (RFC7477)
          | ANY        -- ^ A request for all records the server/cache
                       --   has available
          | UnknownTYPE Word16  -- ^ Unknown type
          deriving (Eq, Ord, Show, Read)

-- | From type to number.
fromTYPE :: TYPE -> Word16
fromTYPE A          =  1
fromTYPE NS         =  2
fromTYPE CNAME      =  5
fromTYPE SOA        =  6
fromTYPE NULL       = 10
fromTYPE PTR        = 12
fromTYPE MX         = 15
fromTYPE TXT        = 16
fromTYPE AAAA       = 28
fromTYPE SRV        = 33
fromTYPE DNAME      = 39
fromTYPE OPT        = 41
fromTYPE DS         = 43
fromTYPE RRSIG      = 46
fromTYPE NSEC       = 47
fromTYPE DNSKEY     = 48
fromTYPE NSEC3      = 50
fromTYPE NSEC3PARAM = 51
fromTYPE TLSA       = 52
fromTYPE CDS        = 59
fromTYPE CDNSKEY    = 60
fromTYPE CSYNC      = 62
fromTYPE ANY        = 255
fromTYPE (UnknownTYPE x) = x

-- | From number to type.
toTYPE :: Word16 -> TYPE
toTYPE  1 = A
toTYPE  2 = NS
toTYPE  5 = CNAME
toTYPE  6 = SOA
toTYPE 10 = NULL
toTYPE 12 = PTR
toTYPE 15 = MX
toTYPE 16 = TXT
toTYPE 28 = AAAA
toTYPE 33 = SRV
toTYPE 39 = DNAME
toTYPE 41 = OPT
toTYPE 43 = DS
toTYPE 46 = RRSIG
toTYPE 47 = NSEC
toTYPE 48 = DNSKEY
toTYPE 50 = NSEC3
toTYPE 51 = NSEC3PARAM
toTYPE 52 = TLSA
toTYPE 59 = CDS
toTYPE 60 = CDNSKEY
toTYPE 62 = CSYNC
toTYPE 255 = ANY
toTYPE x   = UnknownTYPE x
#endif

----------------------------------------------------------------

-- | An enumeration of all possible DNS errors that can occur.
data DNSError =
    -- | The sequence number of the answer doesn't match our query. This
    --   could indicate foul play.
    SequenceNumberMismatch
    -- | The number of retries for the request was exceeded.
  | RetryLimitExceeded
    -- | TCP fallback request timed out.
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
    -- | Network failure.
  | NetworkFailure IOException
    -- | Error is unknown
  | DecodeError String
  | UnknownDNSError
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
  , authAnswer   :: Bool   -- ^ AA (Authoritative Answer) bit - this bit is valid in responses,
                           -- and specifies that the responding name server is an
                           -- authority for the domain name in question section.
  , trunCation   :: Bool   -- ^ TC (Truncated Response) bit - specifies that this message was truncated
                           -- due to length greater than that permitted on the
                           -- transmission channel.
  , recDesired   :: Bool   -- ^ RD (Recursion Desired) bit - this bit may be set in a query and
                           -- is copied into the response.  If RD is set, it directs
                           -- the name server to pursue the query recursively.
                           -- Recursive query support is optional.
  , recAvailable :: Bool   -- ^ RA (Recursion Available) bit - this be is set or cleared in a
                           -- response, and denotes whether recursive query support is
                           -- available in the name server.

  , rcode        :: RCODE  -- ^ Response code.
  , authenData   :: Bool   -- ^ AD (Authenticated Data) bit - (RFC4035, Section 3.2.3).
  , chkDisable   :: Bool   -- ^ CD (Checking Disabled) bit - (RFC4035, Section 3.2.2).
  } deriving (Eq, Show)


-- | Default 'DNSFlags' record suitable for making recursive queries.  By default
-- the RD bit is set, and the AD and CD bits are cleared.
--
defaultDNSFlags :: DNSFlags
defaultDNSFlags = DNSFlags
         { qOrR         = QR_Query
         , opcode       = OP_STD
         , authAnswer   = False
         , trunCation   = False
         , recDesired   = True
         , recAvailable = False
         , authenData   = False
         , chkDisable   = False
         , rcode        = NoErr
         }

-- | Flag operations. This is an instance of 'Monoid'.
-- If they are used with '(<>)', the left value wins.
--
-- >>> mempty :: FlagOp
-- FlagKeep
-- >>> FlagSet <> mempty
-- FlagSet
-- >>> FlagClear <> FlagSet <> mempty
-- FlagClear
-- >>> FlagReset <> FlagClear <> FlagSet <> mempty
-- FlagReset
data FlagOp = FlagSet   -- ^ Flag is set
            | FlagClear -- ^ Flag is unset
            | FlagReset -- ^ Flag is reset to the default value
            | FlagKeep  -- ^ Flag is not changed
            deriving (Eq, Show)

-- $
-- Test associativity of the semigroup operation:
--
-- >>> let ops = [FlagSet, FlagClear, FlagReset, FlagKeep]
-- >>> foldl (&&) True [(a<>b)<>c == a<>(b<>c) | a <- ops, b <- ops, c <- ops]
-- True
--
instance Sem.Semigroup FlagOp where
    FlagKeep <> op = op
    op       <> _  = op

instance Monoid FlagOp where
    mempty = FlagKeep
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

-- | Optional overrides of query-related DNS flags.  The 'Monoid' instance
-- makes it possible to combine the generators 'rdFlag', 'adFlag' and 'cdFlag' to
-- yield all possible combinations of "set", "clear" and "reset" (to default)
-- for each of the bits.
--
-- >>> adFlag FlagSet <> mempty
-- ad:1
-- >>> cdFlag FlagReset <> rdFlag FlagSet <> adFlag FlagClear <> cdFlag FlagSet <> adFlag FlagSet <> mempty
-- rd:1,ad:0
--
data QueryFlags = QueryFlags
    { rdBit :: !FlagOp
    , adBit :: !FlagOp
    , cdBit :: !FlagOp
    }

instance Sem.Semigroup QueryFlags where
    (QueryFlags rd1 ad1 cd1) <> (QueryFlags rd2 ad2 cd2) =
        QueryFlags (rd1 <> rd2) (ad1 <> ad2) (cd1 <> cd2)

instance Monoid QueryFlags where
    mempty = QueryFlags FlagKeep FlagKeep FlagKeep
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

instance Show QueryFlags where
    show (QueryFlags rd ad cd) = List.intercalate "," $ List.filter (/= magic) [
             showFlag "rd" rd
           , showFlag "ad" ad
           , showFlag "cd" cd ]
      where
        magic = ""
        showFlag :: String -> FlagOp -> String
        showFlag nm FlagSet   = nm ++ ":1"
        showFlag nm FlagClear = nm ++ ":0"
        showFlag _  FlagReset = magic
        showFlag _  FlagKeep  = magic

-- | Apply all the query flag overrides to 'defaultDNSFlags', returning the
-- resulting 'DNSFlags' suitable for making queries with the requested flag
-- settings.  This is only needed if you're creating your own 'DNSMessage',
-- the 'Network.DNS.LookupRaw.lookupRawWithFlags' function takes a 'QueryFlags'
-- argument and handles this conversion internally.
--
-- Default overrides can be specified in the resolver configuration by setting
-- the 'Network.DNS.resolvQueryFlags' field of the
-- 'Network.DNS.Resolver.ResolvConf' argument to
-- 'Network.DNS.Resolver.makeResolvSeed'.  These then apply to lookups via
-- resolvers based on the resulting configuration, with the exception of
-- 'Network.DNS.LookupRaw.lookupRawWithFlags' which takes an additional 'QueryFlags'
-- argument to augment the default overrides.
--
queryDNSFlags :: QueryFlags -> DNSFlags
queryDNSFlags (QueryFlags rd ad cd) = d {
      recDesired = toBool rd $ recDesired d
    , authenData = toBool ad $ authenData d
    , chkDisable = toBool cd $ chkDisable d
    }
  where
    d = defaultDNSFlags
    toBool FlagSet   _ = True
    toBool FlagClear _ = False
    toBool _         v = v

-- | Generator of 'QueryFlags' that manipulates the RD bit.
--
rdFlag :: FlagOp -> QueryFlags
rdFlag rd = mempty { rdBit = rd }

-- | Generator of 'QueryFlags' that manipulates the AD bit.
--
adFlag :: FlagOp -> QueryFlags
adFlag ad = mempty { adBit = ad }

-- | Generator of 'QueryFlags' that manipulates the CD bit.
--
cdFlag :: FlagOp -> QueryFlags
cdFlag cd = mempty { cdBit = cd }

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
  -- OPCODE 3 is unassigned
  | OP_NOTIFY -- ^ A zone change notification (RFC1996)
  | OP_UPDATE -- ^ An update request (RFC2136)
  deriving (Eq, Show, Enum, Bounded)

-- | Convert a 16-bit DNS OPCODE number to its internal representation
--
toOPCODE :: Word16 -> Maybe OPCODE
toOPCODE i = case i of
  0 -> Just OP_STD
  1 -> Just OP_INV
  2 -> Just OP_SSR
  4 -> Just OP_NOTIFY
  5 -> Just OP_UPDATE
  _ -> Nothing

-- | Convert the internal representation of a DNS OPCODE to its 16-bit numeric
-- value.
--
fromOPCODE :: OPCODE -> Word16
fromOPCODE OP_STD    = 0
fromOPCODE OP_INV    = 1
fromOPCODE OP_SSR    = 2
fromOPCODE OP_NOTIFY = 4
fromOPCODE OP_UPDATE = 5

----------------------------------------------------------------

#if __GLASGOW_HASKELL__ >= 802
-- | Response code including EDNS0's 12bit ones.
newtype RCODE = RCODE {
    -- | From rcode to number.
    fromRCODE :: Word16
  } deriving (Eq)

-- | Provide an Enum instance for backwards compatibility
instance Enum RCODE where
    fromEnum = fromIntegral . fromRCODE
    toEnum = RCODE . fromIntegral

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
-- | YXDomain - Dynamic update response, a pre-requisite domain that should not
-- exist, does exist.
pattern YXDomain :: RCODE
pattern YXDomain  = RCODE 6
-- | YXRRSet - Dynamic update response, a pre-requisite RRSet that should not
-- exist, does exist.
pattern YXRRSet  :: RCODE
pattern YXRRSet   = RCODE 7
-- | NXRRSet - Dynamic update response, a pre-requisite RRSet that should
-- exist, does not exist.
pattern NXRRSet  :: RCODE
pattern NXRRSet   = RCODE 8
-- | NotAuth - Dynamic update response, the server is not authoritative for the
-- zone named in the Zone Section.
pattern NotAuth  :: RCODE
pattern NotAuth   = RCODE 9
-- | NotZone - Dynamic update response, a name used in the Prerequisite or
-- Update Section is not within the zone denoted by the Zone Section.
pattern NotZone  :: RCODE
pattern NotZone   = RCODE 10
-- | Bad OPT Version (RFC 6891) or TSIG Signature Failure (RFC2845).
pattern BadOpt    :: RCODE
pattern BadOpt     = RCODE 16

-- | Use https://tools.ietf.org/html/rfc2929#section-2.3 names for DNS RCODEs
instance Show RCODE where
    show NoErr     = "NoError"
    show FormatErr = "FormErr"
    show ServFail  = "ServFail"
    show NameErr   = "NXDomain"
    show NotImpl   = "NotImp"
    show Refused   = "Refused"
    show YXDomain  = "YXDomain"
    show YXRRSet   = "YXRRSet"
    show NotAuth   = "NotAuth"
    show NotZone   = "NotZone"
    show BadOpt    = "BADVERS"
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
#else
-- | Response code.
data RCODE
  = NoErr     -- ^ No error condition.
  | FormatErr -- ^ Format error - The name server was
              --   unable to interpret the query.
  | ServFail  -- ^ Server failure - The name server was
              --   unable to process this query due to a
              --   problem with the name server.
  | NameErr   -- ^ Name Error - Meaningful only for
              --   responses from an authoritative name
              --   server, this code signifies that the
              --   domain name referenced in the query does
              --   not exist.
  | NotImpl   -- ^ Not Implemented - The name server does
              --   not support the requested kind of query.
  | Refused   -- ^ Refused - The name server refuses to
              --   perform the specified operation for
              --   policy reasons.  For example, a name
              --   server may not wish to provide the
              --   information to the particular requester,
              --   or a name server may not wish to perform
              --   a particular operation (e.g., zone
              --   transfer) for particular data.
  | YXDomain  -- ^ Dynamic update response, a pre-requisite
              --   domain that should not exist, does exist.
  | YXRRSet   -- ^ Dynamic update response, a pre-requisite
              --   RRSet that should not exist, does exist.
  | NXRRSet   -- ^ Dynamic update response, a pre-requisite
              --   RRSet that should exist, does not exist.
  | NotAuth   -- ^ Dynamic update response, the server is not
              --   authoritative for the zone named in the Zone Section.
  | NotZone   -- ^ Dynamic update response, a name used in the
              --   Prerequisite or Update Section is not within the zone
              --   denoted by the Zone Section.
  | BadOpt    -- ^ Bad OPT Version (RFC 6891) or TSIG Signature
              --   Failure (RFC2845).
  | UnknownRCODE Word16
  deriving (Eq, Ord, Show)

-- | From rcode to number.
fromRCODE :: RCODE -> Word16
fromRCODE NoErr     =  0
fromRCODE FormatErr =  1
fromRCODE ServFail  =  2
fromRCODE NameErr   =  3
fromRCODE NotImpl   =  4
fromRCODE Refused   =  5
fromRCODE YXDomain  =  6
fromRCODE YXRRSet   =  7
fromRCODE NXRRSet   =  8
fromRCODE NotAuth   =  9
fromRCODE NotZone   = 10
fromRCODE BadOpt    = 16
fromRCODE (UnknownRCODE x) = x

-- | From number to rcode.
toRCODE :: Word16 -> RCODE
toRCODE  0 = NoErr
toRCODE  1 = FormatErr
toRCODE  2 = ServFail
toRCODE  3 = NameErr
toRCODE  4 = NotImpl
toRCODE  5 = Refused
toRCODE  6 = YXDomain
toRCODE  7 = YXRRSet
toRCODE  8 = NXRRSet
toRCODE  9 = NotAuth
toRCODE 10 = NotZone
toRCODE 16 = BadOpt
toRCODE  x = UnknownRCODE x

-- | From rcode to number for header (4bits only).
fromRCODEforHeader :: RCODE -> Word16
fromRCODEforHeader rc = fromRCODE rc .&. 0x0f

-- | From number in header to rcode (4bits only).
toRCODEforHeader :: Word16 -> RCODE
toRCODEforHeader w = toRCODE (w .&. 0x0f)
#endif

----------------------------------------------------------------

-- XXX: The Question really should also include the CLASS
--
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

-- | Time to live in second.
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
data RData = RD_A !IPv4            -- ^ IPv4 address
           | RD_NS !Domain         -- ^ An authoritative name serve
           | RD_CNAME !Domain      -- ^ The canonical name for an alias
           | RD_SOA !Domain !Mailbox !Word32 !Word32 !Word32 !Word32 !Word32
                                   -- ^ Marks the start of a zone of authority
           | RD_NULL               -- ^ A null RR (EXPERIMENTAL).
                                   -- Anything can be in a NULL record,
                                   -- for now we just drop this data.
           | RD_PTR !Domain        -- ^ A domain name pointer
           | RD_MX !Word16 !Domain -- ^ Mail exchange
           | RD_TXT !ByteString    -- ^ Text strings
           | RD_AAAA !IPv6         -- ^ IPv6 Address
           | RD_SRV !Word16 !Word16 !Word16 !Domain
                                   -- ^ Server Selection (RFC2782)
           | RD_DNAME !Domain      -- ^ DNAME (RFC6672)
           | RD_OPT ![OData]       -- ^ OPT (RFC6891)
           | RD_DS !Word16 !Word8 !Word8 !ByteString -- ^ Delegation Signer (RFC4034)
           --RD_RRSIG
           --RD_NSEC
           | RD_DNSKEY !Word16 !Word8 !Word8 !ByteString
                                   -- ^ DNSKEY (RFC4034)
           --RD_NSEC3
           | RD_NSEC3PARAM !Word8 !Word8 !Word16 !ByteString
           | RD_TLSA !Word8 !Word8 !Word8 !ByteString
                                   -- ^ TLSA (RFC6698)
           --RD_CDS
           --RD_CDNSKEY
           --RD_CSYNC
           | UnknownRData !ByteString   -- ^ Unknown resource data
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
  show (UnknownRData is) = show is
  show (RD_TLSA use sel mtype dgst) = show use ++ " " ++ show sel ++ " " ++ show mtype ++ " " ++ hexencode dgst
  show (RD_DS t a dt dv) = show t ++ " " ++ show a ++ " " ++ show dt ++ " " ++ hexencode dv
  show RD_NULL = "NULL"
  show (RD_DNSKEY f p a k) = show f ++ " " ++ show p ++ " " ++ show a ++ " " ++ b64encode k
  show (RD_NSEC3PARAM h f i s) = show h ++ " " ++ show f ++ " " ++ show i ++ " " ++ showSalt s
    where
      showSalt ""    = "-"
      showSalt salt  = hexencode salt

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
     , flags = defaultDNSFlags
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

#if __GLASGOW_HASKELL__ >= 802
-- | Default information for EDNS0.
--
-- >>> defaultEDNS0
-- EDNS0 {udpSize = 4096, extRCODE = NoError, dnssecOk = False, options = []}
#else
-- | Default information for EDNS0.
--
-- >>> defaultEDNS0
-- EDNS0 {udpSize = 4096, extRCODE = NoErr, dnssecOk = False, options = []}
#endif
defaultEDNS0 :: EDNS0
defaultEDNS0 = EDNS0 4096 NoErr False []

-- | Maximum UDP size. If 'udpSize' of 'EDNS0' is larger than this,
--   'fromEDNS0' uses this value instead.
--
-- >>> maxUdpSize
-- 16384
maxUdpSize :: Word16
maxUdpSize = 16384

-- | Minimum UDP size. If 'udpSize' of 'EDNS0' is smaller than this,
--   'fromEDNS0' uses this value instead.
--
-- >>> minUdpSize
-- 512
minUdpSize :: Word16
minUdpSize = 512

-- | Generating a resource record for the additional section based on EDNS0.
-- 'DNSFlags' is not generated.
-- Just set the same 'RCODE' to 'DNSFlags'.
fromEDNS0 :: EDNS0 -> ResourceRecord
fromEDNS0 edns = ResourceRecord name' type' class' ttl' rdata'
  where
    name'  = "."
    type'  = OPT
    class' = maxUdpSize `min` (minUdpSize `max` udpSize edns)
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

#if __GLASGOW_HASKELL__ >= 802
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
#else
-- | Option Code (RFC 6891).
data OptCode = ClientSubnet          -- ^ Client subnet (RFC7871)
             | UnknownOptCode Word16 -- ^ Unknown option code
    deriving (Eq, Ord, Show)

-- | From option code to number.
fromOptCode :: OptCode -> Word16
fromOptCode ClientSubnet = 8
fromOptCode (UnknownOptCode x) = x

-- | From number to option code.
toOptCode :: Word16 -> OptCode
toOptCode 8 = ClientSubnet
toOptCode x = UnknownOptCode x
#endif

----------------------------------------------------------------

-- | Optional resource data.
data OData = OD_ClientSubnet Word8 Word8 IP   -- ^ Client subnet (RFC7871)
           | UnknownOData OptCode ByteString  -- ^ Unknown optional type
    deriving (Eq,Show,Ord)
