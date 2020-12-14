{-# OPTIONS_HADDOCK hide #-}

-- | Internal DNS message component encoders for the test-suite.
module Network.DNS.Encode.Internal (
    encodeDNSHeader
  , encodeDNSFlags
  , encodeDomain
  , encodeMailbox
  , encodeResourceRecord
  ) where

import Network.DNS.Encode.Builders
import Network.DNS.Imports
import Network.DNS.StateBinary
import Network.DNS.Types.Internal

-- | Encode DNS flags.
encodeDNSFlags :: DNSFlags -> ByteString
encodeDNSFlags = runSPut . putDNSFlags

-- | Encode DNS header.
encodeDNSHeader :: DNSHeader -> ByteString
encodeDNSHeader = runSPut . putHeader

-- | Encode a domain.
encodeDomain :: Domain -> ByteString
encodeDomain = runSPut . putDomain

-- | Encode a mailbox name.  The first label is separated from the remaining
-- labels by an @'\@'@ rather than a @.@.  This is used for the contact
-- address in the @SOA@ and @RP@ records.
--
encodeMailbox :: Mailbox -> ByteString
encodeMailbox = runSPut . putMailbox

-- | Encode a ResourceRecord.
encodeResourceRecord :: ResourceRecord -> ByteString
encodeResourceRecord rr = runSPut $ putResourceRecord rr
