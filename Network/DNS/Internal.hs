module Network.DNS.Internal where

import Data.Char
import Data.IP
import Data.Maybe

----------------------------------------------------------------

data TYPE = A | AAAA | NS | TXT | MX | CNAME | SOA
          | UNKNOWN Int deriving (Eq, Show, Read)

rrDB :: [(TYPE, Int)]
rrDB = [
    (A,      1)
  , (NS,     2)
  , (CNAME,  5)
  , (SOA,    6)
  , (MX,    15)
  , (TXT,   16)
  , (AAAA,  28)
  ]

rookup                  :: (Eq b) => b -> [(a,b)] -> Maybe a
rookup _    []          =  Nothing
rookup  key ((x,y):xys)
  | key == y          =  Just x
  | otherwise         =  rookup key xys

intToType :: Int -> TYPE
intToType n = maybe (UNKNOWN n) id $ rookup n rrDB
typeToInt :: TYPE -> Int
typeToInt (UNKNOWN x)  = x
typeToInt t = maybe 0 id $ lookup t rrDB

toType :: String -> TYPE
toType = read . map toUpper

----------------------------------------------------------------

data QorR = QR_Query | QR_Response deriving (Eq, Show)

data OPCODE = OP_STD | OP_INV | OP_SSR deriving (Eq, Show, Enum)

data RCODE = NoErr | FormatErr | ServFail | NameErr | NotImpl | Refused deriving (Eq, Show, Enum)

----------------------------------------------------------------

type Domain = String

----------------------------------------------------------------

data Question = Question {
    qname  :: Domain
  , qtype  :: TYPE
  } deriving (Eq, Show)

makeQuestion :: Domain -> TYPE -> Question
makeQuestion dom typ = Question dom typ

----------------------------------------------------------------

data ResourceRecord = ResourceRecord {
    rrname :: Domain
  , rrtype :: TYPE
  , rrttl  :: Int
  , rdlen  :: Int
  , rdata  :: RDATA
  } deriving (Eq, Show)

data RDATA = RD_NS Domain | RD_CNAME Domain | RD_MX Int Domain
           | RD_SOA Domain Domain Int Int Int Int Int
           | RD_A IPv4 | RD_AAAA IPv6
           | RD_OTH [Int] deriving (Eq)

instance Show RDATA where
  show (RD_NS dom) = dom
  show (RD_MX prf dom) = dom ++ " " ++ show prf
  show (RD_CNAME dom) = dom
  show (RD_A a) = show a
  show (RD_AAAA aaaa) = show aaaa
  show (RD_SOA mn _ _ _ _ _ mi) = mn ++ " " ++ show mi
  show (RD_OTH is) = show is

----------------------------------------------------------------

data DNSFlags = DNSFlags {
    qOrR         :: QorR
  , opcode       :: OPCODE
  , authAnswer   :: Bool
  , trunCation   :: Bool
  , recDesired   :: Bool
  , recAvailable :: Bool
  , rcode        :: RCODE
  } deriving (Eq, Show)

data DNSHeader = DNSHeader {
    identifier :: Int
  , flags      :: DNSFlags
  , qdCount    :: Int
  , anCount    :: Int
  , nsCount    :: Int
  , arCount    :: Int
  } deriving (Eq, Show)

data DNSFormat = DNSFormat {
    header     :: DNSHeader
  , question   :: [Question]
  , answer     :: [ResourceRecord]
  , authority  :: [ResourceRecord]
  , additional :: [ResourceRecord]
  } deriving (Eq, Show)

----------------------------------------------------------------

defaultQuery :: DNSFormat
defaultQuery = DNSFormat {
    header = DNSHeader {
       identifier = 0
     , flags = undefined
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
