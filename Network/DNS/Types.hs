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
  , RP
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
  , ResourceData(..)
  , RD_A(..)
  , RD_NS(..)
  , RD_CNAME(..)
  , RD_SOA(..)
  , RD_NULL(..)
  , RD_PTR(..)
  , RD_MX(..)
  , RD_TXT(..)
  , RD_RP(..)
  , RD_AAAA(..)
  , RD_SRV(..)
  , RD_DNAME(..)
  , RD_OPT(..)
  , RD_DS(..)
  , RD_RRSIG(..)
  , RD_NSEC(..)
  , RD_DNSKEY(..)
  , RD_NSEC3(..)
  , RD_NSEC3PARAM(..)
  , RD_TLSA(..)
  , RD_CDS(..)
  , RD_CDNSKEY(..)
  , RD_Unknown(..)
  -- *** RData
  , RData(..)
  , toRData
  , fromRData
  , rdataType
  , SGet
  , SPut
  -- *** Smart constructors
  , rd_a
  , rd_ns
  , rd_cname
  , rd_soa
  , rd_null
  , rd_ptr
  , rd_mx
  , rd_txt
  , rd_rp
  , rd_aaaa
  , rd_srv
  , rd_dname
  , rd_opt
  , rd_ds
  , rd_rrsig
  , rd_nsec
  , rd_dnskey
  , rd_nsec3
  , rd_nsec3param
  , rd_tlsa
  , rd_cds
  , rd_cdnskey
  , rd_unknown
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
  , OPCODE (
    OP_STD
  , OP_INV
  , OP_SSR
  , OP_NOTIFY
  , OP_UPDATE
  )
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
  , OptCode (
    ClientSubnet
  , DAU
  , DHU
  , N3U
  , NSID
  )
  , fromOptCode
  , toOptCode
  , OData (..)
  , OD_NSID(..)
  , OD_DAU(..)
  , OD_DHU(..)
  , OD_N3U(..)
  , OD_ClientSubnet(..)
  , od_nsid
  , od_dau
  , od_dhu
  , od_n3u
  , od_clientSubnet
  , od_ecsGeneric
  , od_unknown
  -- ** DNS Body
  , Question (..)
  -- * DNS Error
  , DNSError (..)
  -- * Other types
  , Mailbox
  -- * Other functions
  , dnsTime
  ) where

import Network.DNS.Types.Internal
import Network.DNS.StateBinary
