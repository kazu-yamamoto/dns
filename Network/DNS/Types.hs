{-|
  Data types for DNS Query and Response. For more information, see <http://www.ietf.org/rfc/rfc1035>.
-}

module Network.DNS.Types (
  -- * Domain
    Domain
  -- * TYPE
  , TYPE (..), intToType, typeToInt, toType
  -- * DNS Error
  , DNSError (..)
  -- * DNS Format
  , DNSFormat (..)
  -- * DNS Header
  , DNSHeader (..)
  -- * DNS Flags
  , DNSFlags (..)
  -- * DNS Body
  , QorR (..)
  , OPCODE (..)
  , RCODE (..)
  , ResourceRecord (..)
  , Question (..)
  , RDATA (..)
  , responseA, responseAAAA
  ) where

import Network.DNS.Internal
