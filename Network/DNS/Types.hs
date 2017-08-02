-- | Data types for DNS Query and Response.
--   For more information, see <http://www.ietf.org/rfc/rfc1035>.

module Network.DNS.Types (
  -- * Domain
    Domain
  -- * Resource Records
  , ResourceRecord (..)
  , RData (..), OData (..)
  -- ** Resource Record Type
  , TYPE (..), intToType, typeToInt
  , OPTTYPE (..), intToOptType, optTypeToInt
  -- ** Other Types
  , CLASS
  , classIN
  , TTL
  -- * DNS Error
  , DNSError (..)
  -- * DNS Message
  , DNSMessage (..)
  , DNSFormat
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
