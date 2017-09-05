{-# LANGUAGE DeriveDataTypeable #-}

module Network.DNS.Internal where

import Control.Exception (Exception)
import Data.Bits ((.&.), shiftR, testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as B64 (encode)
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Builder as L
import qualified Data.ByteString.Lazy as L
import Data.IP (IP, IPv4, IPv6)
import Data.Maybe (fromMaybe)
import Data.Typeable (Typeable)
import Data.Word (Word8, Word16, Word32)

----------------------------------------------------------------

-- | Type for domain.
type Domain = ByteString

-- | Type for a mailbox encoded on the wire as a DNS name, but the first label
-- is conceptually the user name, and sometimes has internal '.' characters
-- that are not label separators.
type Mailbox = ByteString

-- | Return type of composeQuery from Encode, needed in Resolver
type Query = ByteString

----------------------------------------------------------------

-- | Types for resource records.
data TYPE = A          -- ^ IPv4 address
          | AAAA       -- ^ IPv6 Address
          | ANY        -- ^ A request for all records the server/cache
                       --   has available
          | NS         -- ^ An authoritative name serve
          | TXT        -- ^ Text strings
          | MX         -- ^ Mail exchange
          | CNAME      -- ^ The canonical name for an alias
          | SOA        -- ^ Marks the start of a zone of authority
          | PTR        -- ^ A domain name pointer
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
          | NULL       -- ^ A null RR (EXPERIMENTAL)
          | UNKNOWN Word16  -- ^ Unknown type
          deriving (Eq, Show, Read)

-- https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
--
rrDB :: [(TYPE, Word16)]
rrDB = [
    (A,      1)
  , (NS,     2)
  , (CNAME,  5)
  , (SOA,    6)
  , (NULL,  10)
  , (PTR,   12)
  , (MX,    15)
  , (TXT,   16)
  , (AAAA,  28)
  , (SRV,   33)
  , (DNAME, 39) -- RFC 6672
  , (OPT,   41) -- RFC 6891
  , (DS,    43) -- RFC 4034
  , (RRSIG, 46) -- RFC 4034
  , (NSEC,  47) -- RFC 4034
  , (DNSKEY, 48) -- RFC 4034
  , (NSEC3, 40) -- RFC 5155
  , (NSEC3PARAM, 51) -- RFC 5155
  , (TLSA,  52) -- RFC 6698
  , (CDS,   59) -- RFC 7344
  , (CDNSKEY, 60) -- RFC 7344
  , (CSYNC, 62) -- RFC 7477
  , (ANY, 255)
  ]

-- | Option Code (RFC 6891).
data OptCode = ClientSubnet -- ^ Client subnet (RFC7871)
             | OUNKNOWN Int -- ^ Unknown option code
    deriving (Eq)

orDB :: [(OptCode, Int)]
orDB = [
        (ClientSubnet, 8)
       ]

rookup                  :: (Eq b) => b -> [(a,b)] -> Maybe a
rookup _    []          =  Nothing
rookup  key ((x,y):xys)
  | key == y          =  Just x
  | otherwise         =  rookup key xys

-- | From number to type. Naming is for historical reasons.
intToType :: Word16 -> TYPE
intToType n = fromMaybe (UNKNOWN n) $ rookup n rrDB

-- | From type to number. Naming is for historical reasons.
typeToInt :: TYPE -> Word16
typeToInt (UNKNOWN x)  = x
typeToInt t = fromMaybe (error "typeToInt") $ lookup t rrDB

-- | From number to option code.
intToOptCode :: Int -> OptCode
intToOptCode n = fromMaybe (OUNKNOWN n) $ rookup n orDB

-- | From option code to number.
optCodeToInt :: OptCode -> Int
optCodeToInt (OUNKNOWN x)  = x
optCodeToInt t = fromMaybe (error "optCodeToInt") $ lookup t orDB

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

-- | For backward compatibility.
type DNSFormat = DNSMessage

-- | Raw data format for the header of DNS Query and Response.
data DNSHeader = DNSHeader {
    identifier :: Word16    -- ^ An identifier assigned by the program that
                            --   generates any kind of query.
  , flags      :: DNSFlags  -- ^ The second 16bit word.
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
  | BadOpt    -- Fixme: 6 is for Name Exists when it should not
              -- but this is for EDNS0
  deriving (Eq, Ord, Show, Enum, Bounded)

----------------------------------------------------------------

-- | Raw data format for DNS questions.
data Question = Question {
    qname  :: Domain -- ^ A domain name
  , qtype  :: TYPE   -- ^ The type of the query
  } deriving (Eq, Show)

-- | Making "Question".
makeQuestion :: Domain -> TYPE -> Question
makeQuestion = Question

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
data RData = RD_NS Domain        -- ^ An authoritative name serve
           | RD_CNAME Domain     -- ^ The canonical name for an alias
           | RD_DNAME Domain     -- ^ DNAME (RFC6672)
           | RD_MX Word16 Domain -- ^ Mail exchange
           | RD_PTR Domain       -- ^ A domain name pointer
           | RD_SOA Domain Mailbox Word32 Word32 Word32 Word32 Word32
                                 -- ^ Marks the start of a zone of authority
           | RD_A IPv4           -- ^ IPv4 address
           | RD_AAAA IPv6        -- ^ IPv6 Address
           | RD_TXT ByteString   -- ^ Text strings
           | RD_SRV Word16 Word16 Word16 Domain
                                 -- ^ Server Selection (RFC2782)
           | RD_OPT [OData]      -- ^ OPT (RFC6891)
           | RD_OTH ByteString
           | RD_TLSA Word8 Word8 Word8 ByteString
                                 -- ^ TLSA (RFC6698)
           | RD_DS Word16 Word8 Word8 ByteString -- ^ Delegation Signer (RFC4034)
           | RD_NULL             -- ^ A null RR (EXPERIMENTAL).
                                 -- Anything can be in a NULL record,
                                 -- for now we just drop this data.
           | RD_DNSKEY Word16 Word8 Word8 ByteString
                                 -- ^ DNSKEY (RFC4034)
    deriving (Eq, Ord)

-- | Optional resource data.
data OData = OD_ClientSubnet Word8 Word8 IP -- ^ Client subnet (RFC7871)
           | OD_Unknown Int ByteString      -- ^ Unknown optional type
    deriving (Eq,Show,Ord)

-- For OPT pseudo-RR defined in RFC 6891

-- | UDP size for EDNS0 (RFC6891).
orUdpSize :: ResourceRecord -> Word16
orUdpSize rr
  | rrtype rr == OPT = rrclass rr
  | otherwise        = error "Can be used only for OPT"

-- | Extended RCODE for EDNS0 (RFC6891).
orExtRcode :: ResourceRecord -> Word8
orExtRcode rr
  | rrtype rr == OPT = fromIntegral $ shiftR (rrttl rr .&. 0xff000000) 24
  | otherwise        = error "Can be used only for OPT"

-- | Version for EDNS0 (RFC6891).
orVersion :: ResourceRecord -> Word8
orVersion rr
  | rrtype rr == OPT = fromIntegral $ shiftR (rrttl rr .&. 0x00ff0000) 16
  | otherwise        = error "Can be used only for OPT"

-- | DNSSEC OK flag (RFC3225) for EDNS0 (RFC6891).
orDnssecOk :: ResourceRecord -> Bool
orDnssecOk rr
  | rrtype rr == OPT = rrttl rr `testBit` 15
  | otherwise        = error "Can be used only for OPT"

-- | Option resource data for EDNS0 (RFC6891).
orRdata :: ResourceRecord -> [OData]
orRdata (ResourceRecord _ OPT _ _ (RD_OPT odata)) = odata
orRdata _ = error "Can be used only for OPT"

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

-- | Composing a response from IPv4 addresses
responseA :: Word16 -> Question -> [IPv4] -> DNSMessage
responseA ident q ips =
  let hd = header defaultResponse
      dom = qname q
      an = fmap (ResourceRecord dom A classIN 300 . RD_A) ips
  in  defaultResponse {
          header = hd { identifier=ident }
        , question = [q]
        , answer = an
      }

-- | Composing a response from IPv6 addresses
responseAAAA :: Word16 -> Question -> [IPv6] -> DNSMessage
responseAAAA ident q ips =
  let hd = header defaultResponse
      dom = qname q
      an = fmap (ResourceRecord dom AAAA classIN 300 . RD_AAAA) ips
  in  defaultResponse {
          header = hd { identifier=ident }
        , question = [q]
        , answer = an
      }
