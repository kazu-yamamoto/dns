module Network.DNS.Internal where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.Char
import Data.IP
import Data.Maybe

----------------------------------------------------------------

{-|
  Type for domain.
-}
type Domain = ByteString

----------------------------------------------------------------

{-|
  Types for resource records.
-}
data TYPE = A | AAAA | NS | TXT | MX | CNAME | SOA | PTR | SRV
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

{-|
  Raw data format for DNS Query and Response.
-}
data DNSFormat = DNSFormat {
    header     :: DNSHeader
  , question   :: [Question]
  , answer     :: [ResourceRecord]
  , authority  :: [ResourceRecord]
  , additional :: [ResourceRecord]
  } deriving (Eq, Show)

{-|
  Raw data format for the header of DNS Query and Response.
-}
data DNSHeader = DNSHeader {
    identifier :: Int
  , flags      :: DNSFlags
  , qdCount    :: Int
  , anCount    :: Int
  , nsCount    :: Int
  , arCount    :: Int
  } deriving (Eq, Show)

{-|
  Raw data format for the flags of DNS Query and Response.
-}
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

{-|
  Raw data format for DNS questions.
-}
data Question = Question {
    qname  :: Domain
  , qtype  :: TYPE
  } deriving (Eq, Show)

{-|
  Making "Question".
-}
makeQuestion :: Domain -> TYPE -> Question
makeQuestion = Question

----------------------------------------------------------------

{-|
  Raw data format for resource records.
-}
data ResourceRecord = ResourceRecord {
    rrname :: Domain
  , rrtype :: TYPE
  , rrttl  :: Int
  , rdlen  :: Int
  , rdata  :: RDATA
  } deriving (Eq, Show)

{-|
  Raw data format for each type.
-}
data RDATA = RD_NS Domain | RD_CNAME Domain | RD_MX Int Domain | RD_PTR Domain
           | RD_SOA Domain Domain Int Int Int Int Int
           | RD_A IPv4 | RD_AAAA IPv6 | RD_TXT ByteString
           | RD_SRV Int Int Int Domain
           | RD_OTH [Int] deriving (Eq)

instance Show RDATA where
  show (RD_NS dom) = BS.unpack dom
  show (RD_MX prf dom) = BS.unpack dom ++ " " ++ show prf
  show (RD_CNAME dom) = BS.unpack dom
  show (RD_A a) = show a
  show (RD_AAAA aaaa) = show aaaa
  show (RD_TXT txt) = BS.unpack txt
  show (RD_SOA mn _ _ _ _ _ mi) = BS.unpack mn ++ " " ++ show mi
  show (RD_PTR dom) = BS.unpack dom
  show (RD_SRV pri wei prt dom) = show pri ++ " " ++ show wei ++ " " ++ show prt ++ BS.unpack dom
  show (RD_OTH is) = show is

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
