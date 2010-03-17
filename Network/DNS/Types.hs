module Network.DNS.Types (
    TYPE (..), intToType, typeToInt, toType
  , QorR (..)
  , OPCODE (..)
  , RCODE (..)
  , Domain
  , Question (qname,qtype), makeQuestion
  , ResourceRecord (rrname,rrtype,rrttl,rdlen,rdata)
  , RDATA (..)
  , DNSFlags (qOrR,opcode,authAnswer,trunCation,recDesired,recAvailable,rcode)
  , DNSHeader (identifier,flags,qdCount,anCount,nsCount,arCount)
  , DNSFormat (header,question,answer,authority,additional)
  ) where

import Network.DNS.Internal
