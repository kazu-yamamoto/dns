-- | Data types for DNS Query and Response.
--   For more information, see <http://www.ietf.org/rfc/rfc1035>.

module Network.DNS.Types (
  -- * Resource Records
    ResourceRecord (..)
  , Answers
  , AuthorityRecords
  , AdditionalRecords
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
  , AXFR
  , ANY
  , CAA
  )
  , fromTYPE
  , toTYPE
  -- ** Resource Data
  , RData (..)
  , RD_RRSIG(..)
  , dnsTime
  -- * DNS Message
  , DNSMessage (..)
  -- ** Query
  , makeQuery
  , makeEmptyQuery
  , defaultQuery
  -- ** Query Controls
  , QueryControls
  , rdFlag
  , adFlag
  , cdFlag
  , doFlag
  , ednsEnabled
  , ednsSetVersion
  , ednsSetUdpSize
  , ednsSetOptions
  -- *** Flag and OData control operations
  , FlagOp(..)
  , ODataOp(..)
  -- ** Response
  , defaultResponse
  , makeResponse
  -- ** DNS Header
  , DNSHeader (..)
  , Identifier
  -- *** DNS flags
  , DNSFlags (..)
  , QorR (..)
  , defaultDNSFlags
  -- *** OPCODE and RCODE
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
  , BadVers
  , BadKey
  , BadTime
  , BadMode
  , BadName
  , BadAlg
  , BadTrunc
  , BadCookie
  , BadRCODE
  )
  , fromRCODE
  , toRCODE
  -- ** EDNS Pseudo-Header
  , EDNSheader(..)
  , ifEDNS
  , mapEDNS
  -- *** EDNS record
  , EDNS(..)
  , defaultEDNS
  , maxUdpSize
  , minUdpSize
  -- *** EDNS options
  , OData (..)
  , OptCode (
    ClientSubnet
  , DAU
  , DHU
  , N3U
  , NSID
  )
  , fromOptCode
  , toOptCode
  -- ** DNS Body
  , Question (..)
  -- * DNS Error
  , DNSError (..)
  -- * Other types
  , Mailbox
    ) where

import Network.DNS.Types.Internal
