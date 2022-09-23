{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE CPP #-}

module Network.DNS.Types.Internal where

import Control.Exception (Exception, IOException)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BS
import Data.Char (intToDigit)
import qualified Data.Hourglass as H
import Data.IP (IP(..), IPv4, IPv6)
import qualified Data.Semigroup as Sem

import qualified Network.DNS.Base32Hex as B32
import Network.DNS.Imports

-- $setup
-- >>> import Network.DNS

----------------------------------------------------------------

-- | This type holds the /presentation form/ of fully-qualified DNS domain
-- names encoded as ASCII A-labels, with \'.\' separators between labels.
-- Non-printing characters are escaped as @\\DDD@ (a backslash, followed by
-- three decimal digits). The special characters: @ \", \$, (, ), ;, \@,@ and
-- @\\@ are escaped by prepending a backslash.  The trailing \'.\' is optional
-- on input, but is recommended, and is always added when decoding from
-- /wire form/.
--
-- The encoding of domain names to /wire form/, e.g. for transmission in a
-- query, requires the input encodings to be valid, otherwise a 'DecodeError'
-- may be thrown. Domain names received in wire form in DNS messages are
-- escaped to this presentation form as part of decoding the 'DNSMessage'.
--
-- This form is ASCII-only. Any conversion between A-label 'ByteString's,
-- and U-label 'Text' happens at whatever layer maps user input to DNS
-- names, or presents /friendly/ DNS names to the user.  Not all users
-- can read all scripts, and applications that default to U-label form
-- should ideally give the user a choice to see the A-label form.
-- Examples:
--
-- @
-- www.example.org.           -- Ordinary DNS name.
-- \_25.\_tcp.mx1.example.net.  -- TLSA RR initial labels have \_ prefixes.
-- \\001.exotic.example.       -- First label is Ctrl-A!
-- just\\.one\\.label.example.  -- First label is \"just.one.label\"
-- @
--
type Domain = ByteString

-- | Type for a mailbox encoded on the wire as a DNS name, but the first label
-- is conceptually the local part of an email address, and may contain internal
-- periods that are not label separators. Therefore, in mailboxes \@ is used as
-- the separator between the first and second labels, and any \'.\' characters
-- in the first label are not escaped.  The encoding is otherwise the same as
-- 'Domain' above. This is most commonly seen in the /rname/ of @SOA@ records,
-- and is also employed in the @mbox-dname@ field of @RP@ records.
-- On input, if there is no unescaped \@ character in the 'Mailbox', it is
-- reparsed with \'.\' as the first label separator. Thus the traditional
-- format with all labels separated by dots is also accepted, but decoding from
-- wire form always uses \@ between the first label and the domain-part of the
-- address.  Examples:
--
-- @
-- hostmaster\@example.org.  -- First label is simply @hostmaster@
-- john.smith\@examle.com.   -- First label is @john.smith@
-- @
--
type Mailbox = ByteString

----------------------------------------------------------------

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
-- | Responsible Person
pattern RP :: TYPE
pattern RP         = TYPE  17
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
-- | Zone transfer (RFC5936)
pattern AXFR :: TYPE
pattern AXFR       = TYPE 252 -- RFC 5936
-- | A request for all records the server/cache has available
pattern ANY :: TYPE
pattern ANY        = TYPE 255
-- | Certification Authority Authorization (RFC6844)
pattern CAA :: TYPE
pattern CAA        = TYPE 257 -- RFC 6844

-- | From number to type.
toTYPE :: Word16 -> TYPE
toTYPE = TYPE

instance Show TYPE where
    show A          = "A"
    show NS         = "NS"
    show CNAME      = "CNAME"
    show SOA        = "SOA"
    show NULL       = "NULL"
    show PTR        = "PTR"
    show MX         = "MX"
    show TXT        = "TXT"
    show RP         = "RP"
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
    show AXFR       = "AXFR"
    show ANY        = "ANY"
    show CAA        = "CAA"
    show x          = "TYPE" ++ show (fromTYPE x)

----------------------------------------------------------------

-- | An enumeration of all possible DNS errors that can occur.
data DNSError =
    -- | The sequence number of the answer doesn't match our query. This
    --   could indicate foul play.
    SequenceNumberMismatch
    -- | The question section of the response doesn't match our query. This
    --   could indicate foul play.
  | QuestionMismatch
    -- | A zone tranfer, i.e., a request of type AXFR, was attempted with the
    -- "lookup" interface. Zone transfer is different enough from "normal"
    -- requests that it requires a different interface.
  | InvalidAXFRLookup
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
    -- | The server does not support the OPT RR version or content
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


-- | Data type representing the optional EDNS pseudo-header of a 'DNSMessage'
-- When a single well-formed @OPT@ 'ResourceRecord' was present in the
-- message's additional section, it is decoded to an 'EDNS' record and and
-- stored in the message 'ednsHeader' field.  The corresponding @OPT RR@ is
-- then removed from the additional section.
--
-- When the constructor is 'NoEDNS', no @EDNS OPT@ record was present in the
-- message additional section.  When 'InvalidEDNS', the message holds either a
-- malformed OPT record or more than one OPT record, which can still be found
-- in (have not been removed from) the message additional section.
--
-- The EDNS OPT record augments the message error status with an 8-bit field
-- that forms 12-bit extended RCODE when combined with the 4-bit RCODE from the
-- unextended DNS header.  In EDNS messages it is essential to not use just the
-- bare 4-bit 'RCODE' from the original DNS header.  Therefore, in order to
-- avoid potential misinterpretation of the response 'RCODE', when the OPT
-- record is decoded, the upper eight bits of the error status are
-- automatically combined with the 'rcode' of the message header, so that there
-- is only one place in which to find the full 12-bit result.  Therefore, the
-- decoded 'EDNS' pseudo-header, does not hold any error status bits.
--
-- The reverse process occurs when encoding messages.  The low four bits of the
-- message header 'rcode' are encoded into the wire-form DNS header, while the
-- upper eight bits are encoded as part of the OPT record.  In DNS responses with
-- an 'rcode' larger than 15, EDNS extensions SHOULD be enabled by providing a
-- value for 'ednsHeader' with a constructor of 'EDNSheader'.  If EDNS is not
-- enabled in such a message, in order to avoid truncation of 'RCODE' values
-- that don't fit in the non-extended DNS header, the encoded wire-form 'RCODE'
-- is set to 'FormatErr'.
--
-- When encoding messages for transmission, the 'ednsHeader' is used to
-- generate the additional OPT record.  Do not add explicit @OPT@ records
-- to the aditional section, configure EDNS via the 'EDNSheader' instead.
--
-- >>> let getopts eh = mapEDNS eh ednsOptions []
-- >>> let optsin     = [OD_ClientSubnet 24 0 $ read "192.0.2.1"]
-- >>> let masked     = [OD_ClientSubnet 24 0 $ read "192.0.2.0"]
-- >>> let message    = makeEmptyQuery $ ednsSetOptions $ ODataSet optsin
-- >>> let optsout    = getopts. ednsHeader <$> (decode $ encode message)
-- >>> optsout       == Right masked
-- True
--
data EDNSheader = EDNSheader EDNS -- ^ A valid EDNS message
                | NoEDNS          -- ^ A valid non-EDNS message
                | InvalidEDNS     -- ^ Multiple or bad additional @OPT@ RRs
    deriving (Eq, Show)


-- | Return the second argument for EDNS messages, otherwise the third.
ifEDNS :: EDNSheader -- ^ EDNS pseudo-header
       -> a          -- ^ Value to return for EDNS messages
       -> a          -- ^ Value to return for non-EDNS messages
       -> a
ifEDNS (EDNSheader _) a _ = a
ifEDNS             _  _ b = b
{-# INLINE ifEDNS #-}


-- | Return the output of a function applied to the EDNS pseudo-header if EDNS
--   is enabled, otherwise return a default value.
mapEDNS :: EDNSheader  -- ^ EDNS pseudo-header
        -> (EDNS -> a) -- ^ Function to apply to 'EDNS' value
        -> a           -- ^ Default result for non-EDNS messages
        -> a
mapEDNS (EDNSheader eh) f _ = f eh
mapEDNS               _ _ a = a
{-# INLINE mapEDNS #-}


-- | DNS message format for queries and replies.
--
data DNSMessage = DNSMessage {
    header     :: !DNSHeader        -- ^ Header with extended 'RCODE'
  , ednsHeader :: EDNSheader        -- ^ EDNS pseudo-header
  , question   :: [Question]        -- ^ The question for the name server
  , answer     :: Answers           -- ^ RRs answering the question
  , authority  :: AuthorityRecords  -- ^ RRs pointing toward an authority
  , additional :: AdditionalRecords -- ^ RRs holding additional information
  } deriving (Eq, Show)

-- | An identifier assigned by the program that
--   generates any kind of query.
type Identifier = Word16

-- | Raw data format for the header of DNS Query and Response.
data DNSHeader = DNSHeader {
    identifier :: !Identifier -- ^ Query or reply identifier.
  , flags      :: !DNSFlags   -- ^ Flags, OPCODE, and RCODE
  } deriving (Eq, Show)

-- | Raw data format for the flags of DNS Query and Response.
data DNSFlags = DNSFlags {
    qOrR         :: !QorR  -- ^ Query or response.
  , opcode       :: !OPCODE -- ^ Kind of query.
  , authAnswer   :: !Bool  -- ^ AA (Authoritative Answer) bit - this bit is valid in responses,
                           -- and specifies that the responding name server is an
                           -- authority for the domain name in question section.
  , trunCation   :: !Bool  -- ^ TC (Truncated Response) bit - specifies that this message was truncated
                           -- due to length greater than that permitted on the
                           -- transmission channel.
  , recDesired   :: !Bool  -- ^ RD (Recursion Desired) bit - this bit may be set in a query and
                           -- is copied into the response.  If RD is set, it directs
                           -- the name server to pursue the query recursively.
                           -- Recursive query support is optional.
  , recAvailable :: !Bool  -- ^ RA (Recursion Available) bit - this be is set or cleared in a
                           -- response, and denotes whether recursive query support is
                           -- available in the name server.

  , rcode        :: !RCODE -- ^ The full 12-bit extended RCODE when EDNS is in use.
                           -- Should always be zero in well-formed requests.
                           -- When decoding replies, the high eight bits from
                           -- any EDNS response are combined with the 4-bit
                           -- RCODE from the DNS header.  When encoding
                           -- replies, if no EDNS OPT record is provided, RCODE
                           -- values > 15 are mapped to 'FormatErr'.
  , authenData   :: !Bool  -- ^ AD (Authenticated Data) bit - (RFC4035, Section 3.2.3).
  , chkDisable   :: !Bool  -- ^ CD (Checking Disabled) bit - (RFC4035, Section 3.2.2).
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

----------------------------------------------------------------

-- | Boolean flag operations. These form a 'Monoid'.  When combined via
-- `mappend`, as with function composition, the left-most value has
-- the last say.
--
-- >>> mempty :: FlagOp
-- FlagKeep
-- >>> FlagSet <> mempty
-- FlagSet
-- >>> FlagClear <> FlagSet <> mempty
-- FlagClear
-- >>> FlagReset <> FlagClear <> FlagSet <> mempty
-- FlagReset
data FlagOp = FlagSet   -- ^ Set the flag to 1
            | FlagClear -- ^ Clear the flag to 0
            | FlagReset -- ^ Reset the flag to its default value
            | FlagKeep  -- ^ Leave the flag unchanged
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

-- | We don't show options left at their default value.
--
_skipDefault :: String
_skipDefault = ""

-- | Show non-default flag values
--
_showFlag :: String -> FlagOp -> String
_showFlag nm FlagSet   = nm ++ ":1"
_showFlag nm FlagClear = nm ++ ":0"
_showFlag _  FlagReset = _skipDefault
_showFlag _  FlagKeep  = _skipDefault

-- | Combine a list of options for display, skipping default values
--
_showOpts :: [String] -> String
_showOpts os = intercalate "," $ filter (/= _skipDefault) os

----------------------------------------------------------------

-- | Control over query-related DNS header flags. As with function composition,
-- the left-most value has the last say.
--
data HeaderControls = HeaderControls
    { rdBit :: !FlagOp
    , adBit :: !FlagOp
    , cdBit :: !FlagOp
    }
    deriving (Eq)

instance Sem.Semigroup HeaderControls where
    (HeaderControls rd1 ad1 cd1) <> (HeaderControls rd2 ad2 cd2) =
        HeaderControls (rd1 <> rd2) (ad1 <> ad2) (cd1 <> cd2)

instance Monoid HeaderControls where
    mempty = HeaderControls FlagKeep FlagKeep FlagKeep
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

instance Show HeaderControls where
    show (HeaderControls rd ad cd) =
        _showOpts
             [ _showFlag "rd" rd
             , _showFlag "ad" ad
             , _showFlag "cd" cd ]

----------------------------------------------------------------

-- | The default EDNS Option list is empty.  We define two operations, one to
-- prepend a list of options, and another to set a specific list of options.
--
data ODataOp = ODataAdd [OData] -- ^ Add the specified options to the list.
             | ODataSet [OData] -- ^ Set the option list as specified.
             deriving (Eq)

-- | Since any given option code can appear at most once in the list, we
-- de-duplicate by the OPTION CODE when combining lists.
--
_odataDedup :: ODataOp -> [OData]
_odataDedup op =
    nubBy ((==) `on` _odataToOptCode) $
        case op of
            ODataAdd os -> os
            ODataSet os -> os

-- $
-- Test associativity of the OData semigroup operation:
--
-- >>> let ip1 = IPv4 $ read "127.0.0.0"
-- >>> let ip2 = IPv4 $ read "192.0.2.0"
-- >>> let cs1 = OD_ClientSubnet 8 0 ip1
-- >>> let cs2 = OD_ClientSubnet 24 0 ip2
-- >>> let cs3 = OD_ECSgeneric 0 24 0 "foo"
-- >>> let dau1 = OD_DAU [3,5,7,8]
-- >>> let dau2 = OD_DAU [13,14]
-- >>> let dhu1 = OD_DHU [1,2]
-- >>> let dhu2 = OD_DHU [3,4]
-- >>> let nsid = OD_NSID ""
-- >>> let ops1 = [ODataAdd [dau1, dau2, cs1], ODataAdd [dau2, cs2, dhu1]]
-- >>> let ops2 = [ODataSet [], ODataSet [dhu2, cs3], ODataSet [nsid]]
-- >>> let ops = ops1 ++ ops2
-- >>> foldl (&&) True [(a<>b)<>c == a<>(b<>c) | a <- ops, b <- ops, c <- ops]
-- True

instance Sem.Semigroup ODataOp where
    ODataAdd as <> ODataAdd bs = ODataAdd $ as ++ bs
    ODataAdd as <> ODataSet bs = ODataSet $ as ++ bs
    ODataSet as <> _ = ODataSet as

instance Monoid ODataOp where
    mempty = ODataAdd []
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

----------------------------------------------------------------

-- | EDNS query controls.  When EDNS is disabled via @ednsEnabled FlagClear@,
-- all the other EDNS-related overrides have no effect.
--
-- >>> ednsHeader $ makeEmptyQuery $ ednsEnabled FlagClear <> doFlag FlagSet
-- NoEDNS
data EdnsControls = EdnsControls
    { extEn :: !FlagOp         -- ^ Enabled
    , extVn :: !(Maybe Word8)  -- ^ Version
    , extSz :: !(Maybe Word16) -- ^ UDP Size
    , extDO :: !FlagOp         -- ^ DNSSEC OK (DO) bit
    , extOd :: !ODataOp        -- ^ EDNS option list tweaks
    }
    deriving (Eq)

-- | Apply all the query flag overrides to 'defaultDNSFlags', returning the

instance Sem.Semigroup EdnsControls where
    (EdnsControls en1 vn1 sz1 do1 od1) <> (EdnsControls en2 vn2 sz2 do2 od2) =
        EdnsControls (en1 <> en2) (vn1 <|> vn2) (sz1 <|> sz2)
                    (do1 <> do2) (od1 <> od2)

instance Monoid EdnsControls where
    mempty = EdnsControls FlagKeep Nothing Nothing FlagKeep mempty
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

instance Show EdnsControls where
    show (EdnsControls en vn sz d0 od) =
        _showOpts
            [ _showFlag "edns.enabled" en
            , _showWord "edns.version" vn
            , _showWord "edns.udpsize" sz
            , _showFlag "edns.dobit"   d0
            , _showOdOp "edns.options" $ map (show. _odataToOptCode)
                                       $ _odataDedup od ]
      where
        _showWord :: Show a => String -> Maybe a -> String
        _showWord nm w = maybe _skipDefault (\s -> nm ++ ":" ++ show s) w

        _showOdOp :: String -> [String] -> String
        _showOdOp nm os = case os of
            [] -> ""
            _  -> nm ++ ":[" ++ intercalate "," os ++ "]"

----------------------------------------------------------------

-- | Query controls form a 'Monoid', as with function composition, the
-- left-most value has the last say.  The 'Monoid' is generated by two sets of
-- combinators, one that controls query-related DNS header flags, and another
-- that controls EDNS features.
--
-- The header flag controls are: 'rdFlag', 'adFlag' and 'cdFlag'.
--
-- The EDNS feature controls are: 'doFlag', 'ednsEnabled', 'ednsSetVersion',
-- 'ednsSetUdpSize' and 'ednsSetOptions'.  When EDNS is disabled, all the other
-- EDNS-related controls have no effect.
--
-- __Example:__ Disable DNSSEC checking on the server, and request signatures and
-- NSEC records, perhaps for your own independent validation.  The UDP buffer
-- size is set large, for use with a local loopback nameserver on the same host.
--
-- >>> :{
-- mconcat [ adFlag FlagClear
--         , cdFlag FlagSet
--         , doFlag FlagSet
--         , ednsSetUdpSize (Just 8192) -- IPv4 loopback server?
--         ]
-- :}
-- ad:0,cd:1,edns.udpsize:8192,edns.dobit:1
--
-- __Example:__ Use EDNS version 1 (yet to be specified), request nameserver
-- ids from the server, and indicate a client subnet of "192.0.2.1/24".
--
-- >>> :set -XOverloadedStrings
-- >>> let emptyNSID = ""
-- >>> let mask = 24
-- >>> let ipaddr = read "192.0.2.1"
-- >>> :{
-- mconcat [ ednsSetVersion (Just 1)
--         , ednsSetOptions (ODataAdd [OD_NSID emptyNSID])
--         , ednsSetOptions (ODataAdd [OD_ClientSubnet mask 0 ipaddr])
--         ]
-- :}
-- edns.version:1,edns.options:[NSID,ClientSubnet]

data QueryControls = QueryControls
    { qctlHeader :: !HeaderControls
    , qctlEdns   :: !EdnsControls
    }
    deriving (Eq)

instance Sem.Semigroup QueryControls where
    (QueryControls fl1 ex1) <> (QueryControls fl2 ex2) =
        QueryControls (fl1 <> fl2) (ex1 <> ex2)

instance Monoid QueryControls where
    mempty = QueryControls mempty mempty
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

instance Show QueryControls where
    show (QueryControls fl ex) = _showOpts [ show fl, show ex ]

----------------------------------------------------------------

-- | Generator of 'QueryControls' that adjusts the RD bit.
--
-- >>> rdFlag FlagClear
-- rd:0
rdFlag :: FlagOp -> QueryControls
rdFlag rd = mempty { qctlHeader = mempty { rdBit = rd } }

-- | Generator of 'QueryControls' that adjusts the AD bit.
--
-- >>> adFlag FlagSet
-- ad:1
adFlag :: FlagOp -> QueryControls
adFlag ad = mempty { qctlHeader = mempty { adBit = ad } }

-- | Generator of 'QueryControls' that adjusts the CD bit.
--
-- >>> cdFlag FlagSet
-- cd:1
cdFlag :: FlagOp -> QueryControls
cdFlag cd = mempty { qctlHeader = mempty { cdBit = cd } }

-- | Generator of 'QueryControls' that enables or disables EDNS support.
--   When EDNS is disabled, the rest of the 'EDNS' controls are ignored.
--
-- >>> ednsHeader $ makeEmptyQuery $ ednsEnabled FlagClear <> doFlag FlagSet
-- NoEDNS
ednsEnabled :: FlagOp -> QueryControls
ednsEnabled en = mempty { qctlEdns = mempty { extEn = en } }

-- | Generator of 'QueryControls' that adjusts the 'EDNS' version.
-- A value of 'Nothing' makes no changes, while 'Just' @v@ sets
-- the EDNS version to @v@.
--
-- >>> ednsSetVersion (Just 1)
-- edns.version:1
ednsSetVersion :: Maybe Word8 -> QueryControls
ednsSetVersion vn = mempty { qctlEdns = mempty { extVn = vn } }

-- | Generator of 'QueryControls' that adjusts the 'EDNS' UDP buffer size.
-- A value of 'Nothing' makes no changes, while 'Just' @n@ sets the EDNS UDP
-- buffer size to @n@.
--
-- >>> ednsSetUdpSize (Just 2048)
-- edns.udpsize:2048
ednsSetUdpSize :: Maybe Word16 -> QueryControls
ednsSetUdpSize sz = mempty { qctlEdns = mempty { extSz = sz } }

-- | Generator of 'QueryControls' that adjusts the 'EDNS' DnssecOk (DO) bit.
--
-- >>> doFlag FlagSet
-- edns.dobit:1
doFlag :: FlagOp -> QueryControls
doFlag d0 = mempty { qctlEdns = mempty { extDO = d0 } }

-- | Generator of 'QueryControls' that adjusts the list of 'EDNS' options.
--
-- >>> :set -XOverloadedStrings
-- >>> ednsSetOptions (ODataAdd [OD_NSID ""])
-- edns.options:[NSID]
ednsSetOptions :: ODataOp -> QueryControls
ednsSetOptions od = mempty { qctlEdns = mempty { extOd = od } }

----------------------------------------------------------------

-- | Query or response.
data QorR = QR_Query    -- ^ Query.
          | QR_Response -- ^ Response.
          deriving (Eq, Show, Enum, Bounded)

-- | Kind of query.
data OPCODE
  = OP_STD -- ^ A standard query.
  | OP_INV -- ^ An inverse query (inverse queries are deprecated).
  | OP_SSR -- ^ A server status request.
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
  -- OPCODE 3 is unassigned
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

-- | EDNS extended 12-bit response code.  Non-EDNS messages use only the low 4
-- bits.  With EDNS this stores the combined error code from the DNS header and
-- and the EDNS psuedo-header. See 'EDNSheader' for more detail.
newtype RCODE = RCODE {
    -- | Convert an 'RCODE' to its numeric value.
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
-- | Bad OPT Version (BADVERS, RFC 6891).
pattern BadVers   :: RCODE
pattern BadVers    = RCODE 16
-- | Key not recognized [RFC2845]
pattern BadKey    :: RCODE
pattern BadKey     = RCODE 17
-- | Signature out of time window [RFC2845]
pattern BadTime   :: RCODE
pattern BadTime    = RCODE 18
-- | Bad TKEY Mode [RFC2930]
pattern BadMode   :: RCODE
pattern BadMode    = RCODE 19
-- | Duplicate key name [RFC2930]
pattern BadName   :: RCODE
pattern BadName    = RCODE 20
-- | Algorithm not supported [RFC2930]
pattern BadAlg    :: RCODE
pattern BadAlg     = RCODE 21
-- | Bad Truncation [RFC4635]
pattern BadTrunc  :: RCODE
pattern BadTrunc   = RCODE 22
-- | Bad/missing Server Cookie [RFC7873]
pattern BadCookie :: RCODE
pattern BadCookie  = RCODE 23
-- | Malformed (peer) EDNS message, no RCODE available.  This is not an RCODE
-- that can be sent by a peer.  It lies outside the 12-bit range expressible
-- via EDNS.  The low 12-bits are chosen to coincide with 'FormatErr'.  When
-- an EDNS message is malformed, and we're unable to extract the extended RCODE,
-- the header 'rcode' is set to 'BadRCODE'.
pattern BadRCODE  :: RCODE
pattern BadRCODE   = RCODE 0x1001

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
    show BadVers   = "BadVers"
    show BadKey    = "BadKey"
    show BadTime   = "BadTime"
    show BadMode   = "BadMode"
    show BadName   = "BadName"
    show BadAlg    = "BadAlg"
    show BadTrunc  = "BadTrunc"
    show BadCookie = "BadCookie"
    show x         = "RCODE " ++ (show $ fromRCODE x)

-- | Convert a numeric value to a corresponding 'RCODE'.  The behaviour is
-- undefined for values outside the range @[0 .. 0xFFF]@ since the EDNS
-- extended RCODE is a 12-bit value.  Values in the range @[0xF01 .. 0xFFF]@
-- are reserved for private use.
toRCODE :: Word16 -> RCODE
toRCODE = RCODE

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
    rrname  :: !Domain -- ^ Name
  , rrtype  :: !TYPE   -- ^ Resource record type
  , rrclass :: !CLASS  -- ^ Resource record class
  , rrttl   :: !TTL    -- ^ Time to live
  , rdata   :: !RData  -- ^ Resource data
  } deriving (Eq,Show)

----------------------------------------------------------------

-- | Given a 32-bit circle-arithmetic DNS time, and the current absolute epoch
-- time, return the epoch time corresponding to the DNS timestamp.
--
dnsTime :: Word32 -- ^ DNS circle-arithmetic timestamp
        -> Int64  -- ^ current epoch time
        -> Int64  -- ^ absolute DNS timestamp
dnsTime tdns tnow =
    let delta = tdns - fromIntegral tnow
     in if delta > 0x7FFFFFFF -- tdns is in the past?
           then tnow - (0x100000000 - fromIntegral delta)
           else tnow + fromIntegral delta

-- | RRSIG representation.
--
-- As noted in
-- <https://tools.ietf.org/html/rfc4034#section-3.1.5 Section 3.1.5 of RFC 4034>
-- the RRsig inception and expiration times use serial number arithmetic.  As a
-- result these timestamps /are not/ pure values, their meaning is
-- time-dependent!  They depend on the present time and are both at most
-- approximately +\/-68 years from the present.  This ambiguity is not a
-- problem because cached RRSIG records should only persist a few days,
-- signature lifetimes should be *much* shorter than 68 years, and key rotation
-- should result any misconstrued 136-year-old signatures fail to validate.
-- This also means that the interpretation of a time that is exactly half-way
-- around the clock at @now +\/-0x80000000@ is not important, the signature
-- should never be valid.
--
-- The upshot for us is that we need to convert these *impure* relative values
-- to pure absolute values at the moment they are received from from the network
-- (or read from files, ... in some impure I/O context), and convert them back to
-- 32-bit values when encoding.  Therefore, the constructor takes absolute
-- 64-bit representations of the inception and expiration times.
--
-- The 'dnsTime' function performs the requisite conversion.
--
data RD_RRSIG = RDREP_RRSIG
    { rrsigType       :: !TYPE       -- ^ RRtype of RRset signed
    , rrsigKeyAlg     :: !Word8      -- ^ DNSKEY algorithm
    , rrsigNumLabels  :: !Word8      -- ^ Number of labels signed
    , rrsigTTL        :: !Word32     -- ^ Maximum origin TTL
    , rrsigExpiration :: !Int64      -- ^ Time last valid
    , rrsigInception  :: !Int64      -- ^ Time first valid
    , rrsigKeyTag     :: !Word16     -- ^ Signing key tag
    , rrsigZone       :: !Domain     -- ^ Signing domain
    , rrsigValue      :: !ByteString -- ^ Opaque signature
    }
    deriving (Eq, Ord)

instance Show RD_RRSIG where
    show RDREP_RRSIG{..} = unwords
        [ show rrsigType
        , show rrsigKeyAlg
        , show rrsigNumLabels
        , show rrsigTTL
        , showTime rrsigExpiration
        , showTime rrsigInception
        , show rrsigKeyTag
        , BS.unpack rrsigZone
        , _b64encode rrsigValue
        ]
      where
        showTime :: Int64 -> String
        showTime t = H.timePrint fmt $ H.Elapsed $ H.Seconds t
          where
            fmt = [ H.Format_Year4, H.Format_Month2, H.Format_Day2
                  , H.Format_Hour,  H.Format_Minute, H.Format_Second ]

-- | Raw data format for each type.
data RData = RD_A IPv4           -- ^ IPv4 address
           | RD_NS Domain        -- ^ An authoritative name serve
           | RD_CNAME Domain     -- ^ The canonical name for an alias
           | RD_SOA Domain Mailbox Word32 Word32 Word32 Word32 Word32
                                 -- ^ Marks the start of a zone of authority
           | RD_NULL ByteString  -- ^ NULL RR (EXPERIMENTAL, RFC1035).
           | RD_PTR Domain       -- ^ A domain name pointer
           | RD_MX Word16 Domain -- ^ Mail exchange
           | RD_TXT ByteString   -- ^ Text strings
           | RD_RP Mailbox Domain -- ^ Responsible Person (RFC1183)
           | RD_AAAA IPv6        -- ^ IPv6 Address
           | RD_SRV Word16 Word16 Word16 Domain
                                 -- ^ Server Selection (RFC2782)
           | RD_DNAME Domain     -- ^ DNAME (RFC6672)
           | RD_OPT [OData]      -- ^ OPT (RFC6891)
           | RD_DS Word16 Word8 Word8 ByteString -- ^ Delegation Signer (RFC4034)
           | RD_RRSIG RD_RRSIG   -- ^ DNSSEC signature
           | RD_NSEC Domain [TYPE] -- ^ DNSSEC denial of existence NSEC record
           | RD_DNSKEY Word16 Word8 Word8 ByteString
                                 -- ^ DNSKEY (RFC4034)
           | RD_NSEC3 Word8 Word8 Word16 ByteString ByteString [TYPE]
                                 -- ^ DNSSEC hashed denial of existence (RFC5155)
           | RD_NSEC3PARAM Word8 Word8 Word16 ByteString
                                 -- ^ NSEC3 zone parameters (RFC5155)
           | RD_TLSA Word8 Word8 Word8 ByteString
                                 -- ^ TLSA (RFC6698)
           | RD_CDS Word16 Word8 Word8 ByteString
                                 -- ^ Child DS (RFC7344)
           | RD_CDNSKEY Word16 Word8 Word8 ByteString
                                 -- ^ Child DNSKEY (RFC7344)
           | RD_CAA Word8 ByteString ByteString
                                 -- ^ CAA (RFC 6844)
           --RD_CSYNC
           | UnknownRData ByteString   -- ^ Unknown resource data
    deriving (Eq, Ord)

instance Show RData where
  show rd = case rd of
      RD_A                  address -> show address
      RD_NS                 nsdname -> showDomain nsdname
      RD_CNAME                cname -> showDomain cname
      RD_SOA          a b c d e f g -> showSOA a b c d e f g
      RD_NULL                 bytes -> showOpaque bytes
      RD_PTR               ptrdname -> showDomain ptrdname
      RD_MX               pref exch -> showMX pref exch
      RD_TXT             textstring -> showTXT textstring
      RD_RP              mbox dname -> showRP mbox dname
      RD_AAAA               address -> show address
      RD_SRV        pri wei prt tgt -> showSRV pri wei prt tgt
      RD_DNAME               target -> showDomain target
      RD_OPT                options -> show options
      RD_DS          tag alg dalg d -> showDS tag alg dalg d
      RD_RRSIG                rrsig -> show rrsig
      RD_NSEC            next types -> showNSEC next types
      RD_DNSKEY             f p a k -> showDNSKEY f p a k
      RD_NSEC3      a f i s h types -> showNSEC3 a f i s h types
      RD_NSEC3PARAM         a f i s -> showNSEC3PARAM a f i s
      RD_TLSA               u s m d -> showTLSA u s m d
      RD_CDS         tag alg dalg d -> showDS tag alg dalg d
      RD_CDNSKEY            f p a k -> showDNSKEY f p a k
      RD_CAA                  f t v -> showCAA f t v
      UnknownRData            bytes -> showOpaque bytes
    where
      showSalt ""    = "-"
      showSalt salt  = _b16encode salt
      showDomain = BS.unpack
      showSOA mname rname serial refresh retry expire minttl =
          showDomain mname ++ " " ++ showDomain rname ++ " " ++
          show serial ++ " " ++ show refresh ++ " " ++
          show retry ++ " " ++ show expire ++ " " ++ show minttl
      showMX preference exchange =
          show preference ++ " " ++ showDomain exchange
      showTXT bs = '"' : B.foldr dnsesc ['"'] bs
        where
          c2w = fromIntegral . fromEnum
          w2c = toEnum . fromIntegral
          doubleQuote = c2w '"'
          backSlash   = c2w '\\'
          dnsesc c s
              | c == doubleQuote   = '\\' : w2c c : s
              | c == backSlash     = '\\' : w2c c : s
              | c >= 32 && c < 127 =        w2c c : s
              | otherwise          = '\\' : ddd c   s
          ddd c s =
              let (q100, r100) = divMod (fromIntegral c) 100
                  (q10, r10) = divMod r100 10
               in intToDigit q100 : intToDigit q10 : intToDigit r10 : s
      showRP mbox dname = showDomain mbox ++ " " ++ showDomain dname
      showSRV priority weight port target =
          show priority ++ " " ++ show weight ++ " " ++
          show port ++ " " ++ BS.unpack target
      showDS keytag alg digestType digest =
          show keytag ++ " " ++ show alg ++ " " ++
          show digestType ++ " " ++ _b16encode digest
      showNSEC next types =
          unwords $ showDomain next : map show types
      showDNSKEY flags protocol alg key =
          show flags ++ " " ++ show protocol ++ " " ++
          show alg ++ " " ++ _b64encode key
      -- | <https://tools.ietf.org/html/rfc5155#section-3.2>
      showNSEC3 hashalg flags iterations salt nexthash types =
          unwords $ show hashalg : show flags : show iterations :
                    showSalt salt : _b32encode nexthash : map show types
      showNSEC3PARAM hashAlg flags iterations salt =
          show hashAlg ++ " " ++ show flags ++ " " ++
          show iterations ++ " " ++ showSalt salt
      showTLSA usage selector mtype digest =
          show usage ++ " " ++ show selector ++ " " ++
          show mtype ++ " " ++ _b16encode digest
      showCAA flags tag value =
          show flags ++ " " ++ show tag ++ " " ++
          show value
      -- | Opaque RData: <https://tools.ietf.org/html/rfc3597#section-5>
      showOpaque bs = unwords ["\\#", show (BS.length bs), _b16encode bs]

_b16encode, _b32encode, _b64encode :: ByteString -> String
_b16encode = BS.unpack. B16.encode
_b32encode = BS.unpack. B32.encode
_b64encode = BS.unpack. B64.encode

-- | Type alias for resource records in the answer section.
type Answers = [ResourceRecord]

-- | Type alias for resource records in the answer section.
type AuthorityRecords = [ResourceRecord]

-- | Type for resource records in the additional section.
type AdditionalRecords = [ResourceRecord]

----------------------------------------------------------------

-- | A 'DNSMessage' template for queries with default settings for
-- the message 'DNSHeader' and 'EDNSheader'.  This is the initial
-- query message state, before customization via 'QueryControls'.
--
defaultQuery :: DNSMessage
defaultQuery = DNSMessage {
    header = DNSHeader {
       identifier = 0
     , flags = defaultDNSFlags
     }
  , ednsHeader = EDNSheader defaultEDNS
  , question   = []
  , answer     = []
  , authority  = []
  , additional = []
  }

-- | Default response.  When responding to EDNS queries, the response must
-- either be an EDNS response, or else FormatErr must be returned.  The default
-- response message has EDNS disabled ('ednsHeader' set to 'NoEDNS'), it should
-- be updated as appropriate.
--
-- Do not explicitly add OPT RRs to the additional section, instead let the
-- encoder compute and add the OPT record based on the EDNS pseudo-header.
--
-- The 'RCODE' in the 'DNSHeader' should be set to the appropriate 12-bit
-- extended value, which will be split between the primary header and EDNS OPT
-- record during message encoding (low 4 bits in DNS header, high 8 bits in
-- EDNS OPT record).  See 'EDNSheader' for more details.
--
defaultResponse :: DNSMessage
defaultResponse = DNSMessage {
    header = DNSHeader {
       identifier = 0
     , flags = defaultDNSFlags {
              qOrR = QR_Response
            , authAnswer = True
            , recAvailable = True
            , authenData = False
       }
     }
  , ednsHeader = NoEDNS
  , question   = []
  , answer     = []
  , authority  = []
  , additional = []
  }

-- | A query template with 'QueryControls' overrides applied,
-- with just the 'Question' and query 'Identifier' remaining
-- to be filled in.
--
makeEmptyQuery :: QueryControls -- ^ Flag and EDNS overrides
               -> DNSMessage
makeEmptyQuery ctls = defaultQuery {
      header = header'
    , ednsHeader = queryEdns ehctls
    }
  where
    hctls = qctlHeader ctls
    ehctls = qctlEdns ctls
    header' = (header defaultQuery) { flags = queryDNSFlags hctls }

    -- | Apply the given 'FlagOp' to a default boolean value to produce the final
    -- setting.
    --
    applyFlag :: FlagOp -> Bool -> Bool
    applyFlag FlagSet   _ = True
    applyFlag FlagClear _ = False
    applyFlag _         v = v

    -- | Construct a list of 0 or 1 EDNS OPT RRs based on EdnsControls setting.
    --
    queryEdns :: EdnsControls -> EDNSheader
    queryEdns (EdnsControls en vn sz d0 od) =
        let d  = defaultEDNS
         in if en == FlagClear
            then NoEDNS
            else EDNSheader $ d { ednsVersion = fromMaybe (ednsVersion d) vn
                                , ednsUdpSize = fromMaybe (ednsUdpSize d) sz
                                , ednsDnssecOk = applyFlag d0 (ednsDnssecOk d)
                                , ednsOptions  = _odataDedup od
                                }

    -- | Apply all the query flag overrides to 'defaultDNSFlags', returning the
    -- resulting 'DNSFlags' suitable for making queries with the requested flag
    -- settings.  This is only needed if you're creating your own 'DNSMessage',
    -- the 'Network.DNS.LookupRaw.lookupRawCtl' function takes a 'QueryControls'
    -- argument and handles this conversion internally.
    --
    -- Default overrides can be specified in the resolver configuration by setting
    -- the 'Network.DNS.resolvQueryControls' field of the
    -- 'Network.DNS.Resolver.ResolvConf' argument to
    -- 'Network.DNS.Resolver.makeResolvSeed'.  These then apply to lookups via
    -- resolvers based on the resulting configuration, with the exception of
    -- 'Network.DNS.LookupRaw.lookupRawCtl' which takes an additional
    -- 'QueryControls' argument to augment the default overrides.
    --
    queryDNSFlags :: HeaderControls -> DNSFlags
    queryDNSFlags (HeaderControls rd ad cd) = d {
          recDesired = applyFlag rd $ recDesired d
        , authenData = applyFlag ad $ authenData d
        , chkDisable = applyFlag cd $ chkDisable d
        }
      where
        d = defaultDNSFlags

-- | Construct a complete query 'DNSMessage', by combining the 'defaultQuery'
-- template with the specified 'Identifier', and 'Question'.  The
-- 'QueryControls' can be 'mempty' to leave all header and EDNS settings at
-- their default values, or some combination of overrides.  A default set of
-- overrides can be enabled via the 'Network.DNS.Resolver.resolvQueryControls'
-- field of 'Network.DNS.Resolver.ResolvConf'.  Per-query overrides are
-- possible by using 'Network.DNS.LookupRaw.loookupRawCtl'.
--
makeQuery :: Identifier        -- ^ Crypto random request id
          -> Question          -- ^ Question name and type
          -> QueryControls     -- ^ Custom RD\/AD\/CD flags and EDNS settings
          -> DNSMessage
makeQuery idt q ctls = empqry {
      header = (header empqry) { identifier = idt }
    , question = [q]
    }
  where
    empqry = makeEmptyQuery ctls

-- | Construct a query response 'DNSMessage'.
makeResponse :: Identifier
             -> Question
             -> Answers
             -> DNSMessage
makeResponse idt q as = defaultResponse {
      header = header' { identifier = idt }
    , question = [q]
    , answer   = as
    }
  where
    header' = header defaultResponse

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
