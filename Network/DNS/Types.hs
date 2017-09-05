-- | Data types for DNS Query and Response.
--   For more information, see <http://www.ietf.org/rfc/rfc1035>.

module Network.DNS.Types (
  -- * Resource Records
    ResourceRecord (..)
  -- ** Types
  , Domain
  , CLASS
  , classIN
  , TTL
  -- ** Resource Record Types
  , TYPE (..), intToType, typeToInt
  -- ** Resource Data
  , RData (..)
  -- * DNS Message
  , DNSMessage (..)
  , DNSFormat
  -- ** DNS Header
  , DNSHeader (..)
  , QorR (..)
  , DNSFlags (..)
  , OPCODE (..)
  , RCODE (..)
  -- ** DNS Body
  , Question (..)
  -- * DNS Error
  , DNSError (..)
  -- * Response Composers
  , responseA, responseAAAA
  -- * EDNS0
  , OData (..)
  , OptCode (..), intToOptCode, optCodeToInt
  -- ** EDNS0 Converters
  , orUdpSize, orExtRcode, orVersion, orDnssecOk, orRdata
  ) where

import Network.DNS.Internal
