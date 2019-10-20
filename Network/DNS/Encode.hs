-- | DNS message encoder.
--
-- Note: 'Nework.DNS' is a client library, and its focus is on /sending/
-- /queries/, and /receiving/ /replies/.  Thefore, while this module is
-- reasonably adept at query generation, building a DNS server with this
-- module requires additional work to handle message size limits, correct UDP
-- truncation, proper EDNS negotiation, and so on.  Support for server-side DNS
-- is at best rudimentary.
--
-- For sending queries, in most cases you should be using one of the functions
-- from 'Network.DNS.Lookup' and 'Network.DNS.LookupRaw', or lastly, if you
-- want to handle the network reads and writes for yourself (with your own code
-- for UDP retries, TCP fallback, EDNS fallback, ...), then perhaps
-- 'Network.DNS.IO.encodeQuestion' (letting 'Network.DNS' do the lookups for
-- you in an @async@ thread is likely much simpler).
--
module Network.DNS.Encode (
    -- * Encode a DNS query (or response).
    encode
  ) where

import Network.DNS.Imports
import Network.DNS.StateBinary
import Network.DNS.Types
import Network.DNS.Encode.Builders

-- | Encode a 'DNSMessage' for transmission over UDP.  For transmission over
-- TCP encapsulate the result via 'Network.DNS.IO.encodeVC', or use
-- 'Network.DNS.IO.sendVC', which handles this internally.  If any
-- 'ResourceRecord' in the message contains incorrectly encoded 'Domain' name
-- ByteStrings, this function may raise a 'DecodeError'.
--
encode :: DNSMessage -> ByteString
encode = runSPut . putDNSMessage
