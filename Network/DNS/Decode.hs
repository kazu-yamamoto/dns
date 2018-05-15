-- | Decoders for DNS.
module Network.DNS.Decode (
    -- * Decoder
    decode
  , decodeMany
    -- ** Decoder for Each Part
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

decode :: ByteString -> Either DNSError DNSMessage
decode bs = fst <$> runSGet getResponse bs

-- | Parse many length-encoded DNS records, for example, from TCP traffic.

decodeMany :: ByteString -> Either DNSError ([DNSMessage], ByteString)
decodeMany bs = do
    ((bss, _), leftovers) <- runSGetWithLeftovers lengthEncoded bs
    msgs <- mapM decode bss
    return (msgs, leftovers)
  where
    -- Read a list of length-encoded lazy bytestrings
    lengthEncoded :: SGet [ByteString]
    lengthEncoded = many $ do
      len <- getInt16
      getNByteString len

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
decodeResourceRecord :: ByteString -> Either DNSError ResourceRecord
decodeResourceRecord bs = fst <$> runSGet getResourceRecord bs
