{-|
  Data types for DNS Query and Response.
-}

module Network.DNS.Types (
    Domain
  , TYPE (..), intToType, typeToInt, toType
  , DNSFormat, header, question, answer, authority, additional
  , DNSHeader, identifier, flags, qdCount, anCount, nsCount, arCount
  , DNSFlags, qOrR, opcode, authAnswer, trunCation, recDesired, recAvailable, rcode
  , QorR (..)
  , OPCODE (..)
  , RCODE (..)
  , ResourceRecord, rrname, rrtype, rrttl, rdlen, rdata
  , Question, qname, qtype, makeQuestion
  , RDATA (..)
  ) where

import Network.DNS.Internal
