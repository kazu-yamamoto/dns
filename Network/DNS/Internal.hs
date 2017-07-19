{-# LANGUAGE DeriveDataTypeable #-}

module Network.DNS.Internal where

import Control.Exception (Exception)
import Data.ByteString (ByteString)
import Data.IP (IP, IPv4, IPv6)
import Data.Maybe (fromMaybe)
import Data.Typeable (Typeable)
import Data.Word (Word8, Word16, Word32)

----------------------------------------------------------------

-- | Type for domain.
type Domain = ByteString

-- | Return type of composeQuery from Encode, needed in Resolver
type Query = ByteString

----------------------------------------------------------------

-- | Types for resource records.
data TYPE = A
          | AAAA
          | NS
          | TXT
          | MX
          | CNAME
          | SOA
          | PTR
          | SRV
          | DNAME
          | OPT
          | DS
          | RRSIG
          | NSEC
          | DNSKEY
          | NSEC3
          | NSEC3PARAM
          | TLSA
          | CDS
          | CDNSKEY
          | CSYNC
          | UNKNOWN Word16
          deriving (Eq, Show, Read)

-- https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
--
rrDB :: [(TYPE, Word16)]
rrDB = [
    (A,      1)
  , (NS,     2)
  , (CNAME,  5)
  , (SOA,    6)
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
  ]

data OPTTYPE = ClientSubnet
             | OUNKNOWN Int
    deriving (Eq)

orDB :: [(OPTTYPE, Int)]
orDB = [
        (ClientSubnet, 8)
       ]

rookup                  :: (Eq b) => b -> [(a,b)] -> Maybe a
rookup _    []          =  Nothing
rookup  key ((x,y):xys)
  | key == y          =  Just x
  | otherwise         =  rookup key xys

intToType :: Word16 -> TYPE
intToType n = fromMaybe (UNKNOWN n) $ rookup n rrDB
typeToInt :: TYPE -> Word16
typeToInt (UNKNOWN x)  = x
typeToInt t = fromMaybe (error "typeToInt") $ lookup t rrDB

intToOptType :: Int -> OPTTYPE
intToOptType n = fromMaybe (OUNKNOWN n) $ rookup n orDB
optTypeToInt :: OPTTYPE -> Int
optTypeToInt (OUNKNOWN x)  = x
optTypeToInt t = fromMaybe (error "optTypeToInt") $ lookup t orDB

----------------------------------------------------------------

-- | An enumeration of all possible DNS errors that can occur.
data DNSError =
    -- | The sequence number of the answer doesn't match our query. This
    --   could indicate foul play.
    SequenceNumberMismatch
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
  deriving (Eq, Show, Typeable)

instance Exception DNSError

-- | Raw data format for DNS Query and Response.
data DNSMessage = DNSMessage {
    header     :: DNSHeader
  , question   :: [Question]
  , answer     :: [ResourceRecord]
  , authority  :: [ResourceRecord]
  , additional :: [ResourceRecord]
  } deriving (Eq, Show)

-- | For backward compatibility.
type DNSFormat = DNSMessage

-- | Raw data format for the header of DNS Query and Response.
data DNSHeader = DNSHeader {
    identifier :: Word16
  , flags      :: DNSFlags
  } deriving (Eq, Show)

-- | Raw data format for the flags of DNS Query and Response.
data DNSFlags = DNSFlags {
    qOrR         :: QorR
  , opcode       :: OPCODE
  , authAnswer   :: Bool
  , trunCation   :: Bool
  , recDesired   :: Bool
  , recAvailable :: Bool
  , rcode        :: RCODE
  , authenData   :: Bool
  } deriving (Eq, Show)

----------------------------------------------------------------

data QorR = QR_Query | QR_Response deriving (Eq, Show, Enum, Bounded)

data OPCODE
  = OP_STD
  | OP_INV
  | OP_SSR
  deriving (Eq, Show, Enum, Bounded)

data RCODE
  = NoErr
  | FormatErr
  | ServFail
  | NameErr
  | NotImpl
  | Refused
  | BadOpt
  deriving (Eq, Ord, Show, Enum, Bounded)

----------------------------------------------------------------

-- | Raw data format for DNS questions.
data Question = Question {
    qname  :: Domain
  , qtype  :: TYPE
  } deriving (Eq, Show)

-- | Making "Question".
makeQuestion :: Domain -> TYPE -> Question
makeQuestion = Question

----------------------------------------------------------------

-- | Raw data format for resource records.
data ResourceRecord
    = ResourceRecord Domain TYPE Word32 RData
    | OptRecord Word16 Bool Word8 RData
    deriving (Eq,Show)

getRdata :: ResourceRecord -> RData
getRdata (ResourceRecord _ _ _ rdata) = rdata
getRdata (OptRecord _ _ _ rdata) = rdata

-- | Raw data format for each type.
data RData = RD_NS Domain
           | RD_CNAME Domain
           | RD_DNAME Domain
           | RD_MX Word16 Domain
           | RD_PTR Domain
           | RD_SOA Domain Domain Word32 Word32 Word32 Word32 Word32
           | RD_A IPv4
           | RD_AAAA IPv6
           | RD_TXT ByteString
           | RD_SRV Word16 Word16 Word16 Domain
           | RD_OPT [OData]
           | RD_OTH ByteString
           | RD_TLSA Word8 Word8 Word8 ByteString
           | RD_DS Word16 Word8 Word8 ByteString
    deriving (Eq, Ord, Show)

data OData = OD_ClientSubnet Word8 Word8 IP
           | OD_Unknown Int ByteString
    deriving (Eq,Show,Ord)

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

responseA :: Word16 -> Question -> [IPv4] -> DNSMessage
responseA ident q ips =
  let hd = header defaultResponse
      dom = qname q
      an = fmap (ResourceRecord dom A 300 . RD_A) ips
  in  defaultResponse {
          header = hd { identifier=ident }
        , question = [q]
        , answer = an
      }

responseAAAA :: Word16 -> Question -> [IPv6] -> DNSMessage
responseAAAA ident q ips =
  let hd = header defaultResponse
      dom = qname q
      an = fmap (ResourceRecord dom AAAA 300 . RD_AAAA) ips
  in  defaultResponse {
          header = hd { identifier=ident }
        , question = [q]
        , answer = an
      }
