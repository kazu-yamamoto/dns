{-# LANGUAGE DeriveDataTypeable, DeriveFunctor, DeriveFoldable #-}

module Network.DNS.Internal where

import Control.Exception (Exception)
import Control.Applicative
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.Char (toUpper)
import Data.IP (IPv4, IPv6, IP(..))
import Data.Maybe (fromJust, fromMaybe)
import Data.Typeable (Typeable)
import Data.Foldable (Foldable)
import Data.Traversable

----------------------------------------------------------------

-- | Type for domain.
type Domain = ByteString

----------------------------------------------------------------

-- | Types for resource records.
data TYPE = A | AAAA | NS | TXT | MX | CNAME | SOA | PTR | SRV | DNAME | OPTREC
          | UNKNOWN Int deriving (Eq, Show, Read)

rrDB :: [(TYPE, Int)]
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
  , (DNAME, 39) -- RFC 2672
  , (OPTREC, 41) -- RFC 6891
  ]

rookup                  :: (Eq b) => b -> [(a,b)] -> Maybe a
rookup _    []          =  Nothing
rookup  key ((x,y):xys)
  | key == y          =  Just x
  | otherwise         =  rookup key xys

intToType :: Int -> TYPE
intToType n = fromMaybe (UNKNOWN n) $ rookup n rrDB
typeToInt :: TYPE -> Int
typeToInt (UNKNOWN x)  = x
typeToInt t = fromMaybe 0 $ lookup t rrDB

toType :: String -> TYPE
toType = read . map toUpper

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
    -- | Meaningful only for responses from an authoritative name
    -- server, this code signifies that the
    -- domain name referenced in the query does not exist.
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
  deriving (Eq, Show, Typeable)

instance Exception DNSError

-- | Raw data format for DNS Query and Response.
data DNSMessage a = DNSFormat {
    header     :: DNSHeader
  , question   :: [Question]
  , answer     :: [RR a]
  , authority  :: [RR a]
  , additional :: [RR a]
  } deriving (Eq, Show, Functor, Foldable)

type DNSFormat = DNSMessage RDATA

instance Traversable DNSMessage where
  sequenceA dns = liftA3 build answer' authority' additional'
    where
      answer'     = traverse sequenceA $ answer dns
      authority'  = traverse sequenceA $ authority dns
      additional' = traverse sequenceA $ additional dns
      build ans auth add = cast { answer     = ans
                                , authority  = auth
                                , additional = add }
        where
          cast = error "unhandled case in sequenceA (DNSMessage)" <$> dns

-- | Like 'fmap' except that RR 'TYPE' context is available
--   within the map.
dnsMapWithType :: (TYPE -> a -> b) -> DNSMessage a -> DNSMessage b
dnsMapWithType parse dns =
    cast { answer     = mapParse $ answer dns
         , authority  = mapParse $ authority dns
         , additional = mapParse $ additional dns
         }
  where
    cast = error "unhandled case in dnsMapWithType" <$> dns
    mapParse = map (rrMapWithType parse)

-- | Behaves exactly like a regular 'traverse' except that the traversing
--   function also has access to the RR 'TYPE' associated with a value.
dnsTraverseWithType ::
    Applicative f =>
    (TYPE -> a -> f b) -> DNSMessage a -> f (DNSMessage b)
dnsTraverseWithType parse = sequenceA . dnsMapWithType parse


-- | Raw data format for the header of DNS Query and Response.
data DNSHeader = DNSHeader {
    identifier :: Int
  , flags      :: DNSFlags
  , qdCount    :: Int
  , anCount    :: Int
  , nsCount    :: Int
  , arCount    :: Int
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
  } deriving (Eq, Show)

----------------------------------------------------------------

data QorR = QR_Query | QR_Response deriving (Eq, Show)

data OPCODE = OP_STD | OP_INV | OP_SSR deriving (Eq, Show, Enum)

data RCODE = NoErr | FormatErr | ServFail | NameErr | NotImpl | Refused deriving (Eq, Show, Enum)

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
data RR a = ResourceRecord {
    rrname :: Domain
  , rrtype :: TYPE
  , rrttl  :: Int
  , rdlen  :: Int
  , rdata  :: a
  } deriving (Eq, Show, Functor, Foldable)

type ResourceRecord = RR RDATA

data OptType = OTClientSubnet
             | OTOther Int
    deriving (Show, Eq)

optTable :: [(OptType, Int)]
optTable = [(OTClientSubnet, 8)
           ]

intToOptType :: Int -> OptType
intToOptType i = fromMaybe (OTOther i) (rookup i optTable)

optTypeToInt :: OptType -> Int
optTypeToInt (OTOther i) = i
optTypeToInt t = fromJust $ lookup t optTable

data OptValue = ClientSubnet Int Int IP -- Source Mask / Scope Mask / IP
              | Other Int ByteString
    deriving (Eq,Show)

-- | Raw data format for each type.
data RD a = RD_NS Domain | RD_CNAME Domain | RD_DNAME Domain
           | RD_MX Int Domain | RD_PTR Domain
           | RD_SOA Domain Domain Int Int Int Int Int
           | RD_A IPv4 | RD_AAAA IPv6 | RD_TXT ByteString
           | RD_SRV Int Int Int Domain
           | RD_OPT [OptValue]
           | RD_OTH a deriving (Eq, Functor, Foldable)

type RDATA = RD [Int]

instance Traversable RD where
  sequenceA (RD_OTH a) = RD_OTH <$> a
  sequenceA rd         = pure cast
    where
        cast = error "unhandled case in sequenceA (RD)" <$> rd

instance Show a => Show (RD a) where
  show (RD_NS dom) = BS.unpack dom
  show (RD_MX prf dom) = BS.unpack dom ++ " " ++ show prf
  show (RD_CNAME dom) = BS.unpack dom
  show (RD_DNAME dom) = BS.unpack dom
  show (RD_A a) = show a
  show (RD_AAAA aaaa) = show aaaa
  show (RD_TXT txt) = BS.unpack txt
  show (RD_SOA mn _ _ _ _ _ mi) = BS.unpack mn ++ " " ++ show mi
  show (RD_PTR dom) = BS.unpack dom
  show (RD_SRV pri wei prt dom) = show pri ++ " " ++ show wei ++ " " ++ show prt ++ BS.unpack dom
  show (RD_OPT vs) = show vs
  show (RD_OTH is) = show is

instance Traversable RR where
  sequenceA rr = (\x -> fmap (const x) rr) <$> rdata rr

-- | Like 'fmap' except that RR 'TYPE' context is available
--   within the map.
rrMapWithType :: (TYPE -> a -> b) -> RR a -> RR b
rrMapWithType parse rr = parse (rrtype rr) <$> rr

----------------------------------------------------------------

defaultQuery :: DNSFormat
defaultQuery = DNSFormat {
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
         }
     , qdCount = 0
     , anCount = 0
     , nsCount = 0
     , arCount = 0
     }
  , question   = []
  , answer     = []
  , authority  = []
  , additional = []
  }

defaultResponse :: DNSFormat
defaultResponse =
  let hd = header defaultQuery
      flg = flags hd
  in  defaultQuery {
        header = hd {
          flags = flg {
              qOrR = QR_Response
            , authAnswer = True
            , recAvailable = True
            }
        }
      }

responseA :: Int -> Question -> IPv4 -> DNSFormat
responseA ident q ip =
  let hd = header defaultResponse
      dom = qname q
      an = ResourceRecord dom A 300 4 (RD_A ip)
  in  defaultResponse {
          header = hd { identifier=ident, qdCount = 1, anCount = 1 }
        , question = [q]
        , answer = [an]
      }

responseAAAA :: Int -> Question -> IPv6 -> DNSFormat
responseAAAA ident q ip =
  let hd = header defaultResponse
      dom = qname q
      an = ResourceRecord dom AAAA 300 16 (RD_AAAA ip)
  in  defaultResponse {
          header = hd { identifier=ident, qdCount = 1, anCount = 1 }
        , question = [q]
        , answer = [an]
      }
