{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

module Network.DNS.Types.Message where

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
