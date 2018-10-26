{-# LANGUAGE OverloadedStrings #-}

module Network.DNS.Decode.Internal (
    -- ** Internal message component decoders for tests
    decodeDNSHeader
  , decodeDNSFlags
  , decodeDomain
  , decodeMailbox
  , decodeResourceRecordAt
  , decodeResourceRecord
  ) where

import Network.DNS.Imports
import Network.DNS.StateBinary
import Network.DNS.Types
import Network.DNS.Decode.Parsers

----------------------------------------------------------------

-- | Decode the 'DNSFlags' field of 'DNSHeader'.  This is an internal function
-- exposed only for testing.
--
decodeDNSFlags :: ByteString -> Either DNSError DNSFlags
decodeDNSFlags bs = fst <$> runSGet getDNSFlags bs

-- | Decode the 'DNSHeader' of a message.  This is an internal function.
-- exposed only for testing.
--
decodeDNSHeader :: ByteString -> Either DNSError DNSHeader
decodeDNSHeader bs = fst <$> runSGet getHeader bs

-- | Decode a domain name.  Since DNS names may use name compression, it is not
-- generally possible to decode the names separately from the enclosing DNS
-- message.  This is an internal function exposed only for testing.
--
decodeDomain :: ByteString -> Either DNSError Domain
decodeDomain bs = fst <$> runSGet getDomain bs

-- | Decode a mailbox name (the SOA record /mrname/ field).  Since DNS names
-- may use name compression, it is not generally possible to decode the names
-- separately from the enclosing DNS message.  This is an internal function.
--
decodeMailbox :: ByteString -> Either DNSError Mailbox
decodeMailbox bs = fst <$> runSGet getMailbox bs

-- | Decoding resource records.

-- | Decode a resource record (RR) with any DNS timestamps interpreted at the
-- nominal epoch time (see 'decodeAt').  Since RRs may use name compression,
-- it is not generally possible to decode resource record separately from the
-- enclosing DNS message.  This is an internal function.
--
decodeResourceRecord :: ByteString -> Either DNSError ResourceRecord
decodeResourceRecord bs = fst <$> runSGet getResourceRecord bs

-- | Decode a resource record (RR) with DNS timestamps interpreted at the
-- supplied epoch time.  Since RRs may use DNS name compression, it is not
-- generally possible to decode resource record separately from the enclosing
-- DNS message.  This is an internal function.
--
decodeResourceRecordAt :: Int64      -- ^ current epoch time
                       -> ByteString -- ^ encoded resource record
                       -> Either DNSError ResourceRecord
decodeResourceRecordAt t bs = fst <$> runSGetAt t getResourceRecord bs
