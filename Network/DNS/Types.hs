{-|
  Data types for DNS Query and Response. For more information, see <http://www.ietf.org/rfc/rfc1035>.
-}

module Network.DNS.Types (
  -- * Domain
    Domain
  -- * TYPE
  , TYPE (..), intToType, typeToInt, toType
  -- * DNS Format
  , DNSFormat (DNSFormat), header, question, answer, authority, additional
  -- * DNS Header
  , DNSHeader (DNSHeader), identifier, flags, qdCount, anCount, nsCount, arCount
  -- * DNS Flags
  , DNSFlags (DNSFlags), qOrR, opcode, authAnswer, trunCation, recDesired, recAvailable, rcode
  -- * DNS Body
  , QorR (..)
  , OPCODE (..)
  , RCODE (..)
  , ResourceRecord (ResourceRecord), rrname, rrtype, rrttl, rdlen, rdata
  , Question (Question), qname, qtype, makeQuestion
  , RDATA (..)
  , responseA, responseAAAA
  ) where

import Network.DNS.Internal
