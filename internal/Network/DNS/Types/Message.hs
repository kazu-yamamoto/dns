{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

module Network.DNS.Types.Message where

import qualified Data.Semigroup as Sem

import Network.DNS.Imports
import Network.DNS.Types.Base
import Network.DNS.Types.EDNS
import Network.DNS.Types.RData

-- $setup
-- >>> import Network.DNS

----------------------------------------------------------------

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

----------------------------------------------------------------

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
    qOrR         :: !QorR   -- ^ Query or response.
  , opcode       :: !OPCODE -- ^ Kind of query.
  , authAnswer   :: !Bool   -- ^ AA (Authoritative Answer) bit - this bit is valid in responses,
                            -- and specifies that the responding name server is an
                            -- authority for the domain name in question section.
  , trunCation   :: !Bool   -- ^ TC (Truncated Response) bit - specifies that this message was truncated
                            -- due to length greater than that permitted on the
                            -- transmission channel.
  , recDesired   :: !Bool   -- ^ RD (Recursion Desired) bit - this bit may be set in a query and
                            -- is copied into the response.  If RD is set, it directs
                            -- the name server to pursue the query recursively.
                            -- Recursive query support is optional.
  , recAvailable :: !Bool   -- ^ RA (Recursion Available) bit - this be is set or cleared in a
                            -- response, and denotes whether recursive query support is
                            -- available in the name server.

  , rcode        :: !RCODE  -- ^ The full 12-bit extended RCODE when EDNS is in use.
                            -- Should always be zero in well-formed requests.
                            -- When decoding replies, the high eight bits from
                            -- any EDNS response are combined with the 4-bit
                            -- RCODE from the DNS header.  When encoding
                            -- replies, if no EDNS OPT record is provided, RCODE
                            -- values > 15 are mapped to 'FormatErr'.
  , authenData   :: !Bool   -- ^ AD (Authenticated Data) bit - (RFC4035, Section 3.2.3).
  , chkDisable   :: !Bool   -- ^ CD (Checking Disabled) bit - (RFC4035, Section 3.2.2).
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

----------------------------------------------------------------

-- | Kind of query.
newtype OPCODE = OPCODE {
    -- | Convert an 'OPCODE' to its numeric value.
    fromOPCODE :: Word16
  } deriving (Eq, Show)

-- | A standard query.
pattern OP_STD    :: OPCODE
pattern OP_STD     = OPCODE 0
-- | An inverse query (inverse queries are deprecated).
pattern OP_INV    :: OPCODE
pattern OP_INV     = OPCODE 1
-- | A server status request.
pattern OP_SSR    :: OPCODE
pattern OP_SSR     = OPCODE 2
-- OPCODE 3 is not assigned
-- | A zone change notification (RFC1996)
pattern OP_NOTIFY :: OPCODE
pattern OP_NOTIFY  = OPCODE 4
-- | An update request (RFC2136)
pattern OP_UPDATE :: OPCODE
pattern OP_UPDATE = OPCODE 5

-- | Convert a 16-bit DNS OPCODE number to its internal representation
--
toOPCODE :: Word16 -> OPCODE
toOPCODE = OPCODE

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
