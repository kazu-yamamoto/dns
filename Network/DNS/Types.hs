-- | Data types for DNS Query and Response.
--   For more information, see <http://www.ietf.org/rfc/rfc1035>.

module Network.DNS.Types (
  -- * Domain
    Domain
  -- * Resource Records
  , ResourceRecord
  , RR (..)
  , RDATA
  , RD (..)
  , rrMapWithType
  -- ** Resource Record Type
  , TYPE (..), intToType, typeToInt, toType
  -- ** EDNS0 Opt Type
  , OptValue (..)
  -- * DNS Error
  , DNSError (..)
  -- * DNS Format
  , DNSFormat
  , DNSMessage (..)
  , dnsMapWithType
  , dnsTraverseWithType
  -- * DNS Header
  , DNSHeader (..)
  -- * DNS Flags
  , DNSFlags (..)
  -- * DNS Body
  , QorR (..)
  , OPCODE (..)
  , RCODE (..)
  , Question (..)
  , responseA, responseAAAA
  ) where

import Network.DNS.Internal
