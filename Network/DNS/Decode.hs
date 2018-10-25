-- | Decoders for DNS.
module Network.DNS.Decode (
    -- * Decoder
    decodeAt
  , decodeManyAt
  , decode
  , decodeMany
    -- ** Decoder for Each Part
  , decodeResourceRecordAt
  , decodeResourceRecord
  , decodeDNSHeader
  , decodeDNSFlags
  , decodeDomain
  , decodeMailbox
  ) where

import Network.DNS.Decode.Internal
import Network.DNS.Imports
import Network.DNS.StateBinary
import Network.DNS.Types

----------------------------------------------------------------

-- | Decoding DNS query or response.

-- | Decode an input buffer containing a single encoded DNS message.  DNS
-- /circle-arithmetic/ timestamps (e.g. in RRSIG records) are interpreted
-- at the supplied epoch time.
--
decodeAt :: Int64      -- ^ current epoch time
         -> ByteString -- ^ input encoded buffer
         -> Either DNSError DNSMessage
decodeAt t bs = fst <$> runSGetAt t getResponse bs

-- | Decode an input buffer containing a single encoded DNS message.  DNS
-- /circle-arithmetic/ timestamps (e.g. in RRSIG records) are interpreted at a
-- nominal time in the year 2078 chosen to give correct dates for timestamps
-- over a 136 year time range from the date the root zone was signed on the
-- 15th of July 2010 until the 21st of August in 2146.  Outside this range the
-- output is off by some non-zero multiple 2\^32 seconds.
--
decode :: ByteString -> Either DNSError DNSMessage
decode bs = fst <$> runSGet getResponse bs

-- | Parse many length-encoded DNS records, for example, from TCP traffic.

-- | Decode a buffer containing multiple encoded DNS messages each preceded by
-- a 16-bit length in network byte order.  DNS /circle-arithmetic/ timestamps
-- (e.g. in RRSIG records) are interpreted at the supplied epoch time.
--
decodeManyAt :: Int64      -- ^ current epoch time
             -> ByteString -- ^ input buffer
             -> Either DNSError ([DNSMessage], ByteString)
decodeManyAt t bs = decodeMParse (decodeAt t) bs

-- | Decode a buffer containing multiple encoded DNS messages each preceded by
-- a 16-bit length in network byte order.  DNS /circle-arithmetic/ timestamps
-- (e.g. in RRSIG records) are interpreted based on a nominal time in the year
-- 2078 chosen to give correct dates for DNS timestamps over a 136 year time
-- range from the date the root zone was signed on the 15th of July 2010 until
-- the 21st of August in 2146.  Outside this date range the output is off by
-- some non-zero multiple 2\^32 seconds.
--
decodeMany :: ByteString -- ^ input buffer
           -> Either DNSError ([DNSMessage], ByteString)
decodeMany bs = decodeMParse decode bs


-- | Decode multiple messages using the given parser.
--
decodeMParse :: (ByteString -> Either DNSError DNSMessage)
             -> ByteString
             -> Either DNSError ([DNSMessage], ByteString)
decodeMParse decoder bs = do
    ((bss, _), leftovers) <- runSGetWithLeftovers lengthEncoded bs
    msgs <- mapM decoder bss
    return (msgs, leftovers)
  where
    -- Read a list of length-encoded bytestrings
    lengthEncoded :: SGet [ByteString]
    lengthEncoded = many $ getInt16 >>= getNByteString

-- | Decoding DNS flags.
decodeDNSFlags :: ByteString -> Either DNSError DNSFlags
decodeDNSFlags bs = fst <$> runSGet getDNSFlags bs

-- | Decoding DNS header.
decodeDNSHeader :: ByteString -> Either DNSError DNSHeader
decodeDNSHeader bs = fst <$> runSGet getHeader bs

-- | Decoding domain.
decodeDomain :: ByteString -> Either DNSError Domain
decodeDomain bs = fst <$> runSGet getDomain bs

-- | Decoding mailbox.
decodeMailbox :: ByteString -> Either DNSError Mailbox
decodeMailbox bs = fst <$> runSGet getMailbox bs

-- | Decoding resource record.

-- | Decode a resource record (RR) with any DNS timestamps interpreted at the
-- nominal epoch time (see 'decodeAt').  Since RRs may use name compression,
-- it is not generally possible to decode resource record separately from the
-- enclosing DNS message.  This is an internal function.
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
