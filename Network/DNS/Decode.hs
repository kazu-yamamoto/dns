{-# LANGUAGE CPP #-}

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

import Control.Applicative (many)
import Data.ByteString (ByteString)
import Network.DNS.StateBinary
import Network.DNS.Types
import Network.DNS.Decode.Internal

#if __GLASGOW_HASKELL__ < 709
import Control.Applicative
#endif

----------------------------------------------------------------

-- | Decoding DNS query or response.

decode :: ByteString -> Either String DNSMessage
decode bs = fst <$> runSGet getResponse bs

-- | Parse many length-encoded DNS records, for example, from TCP traffic.

decodeMany :: ByteString -> Either String ([DNSMessage], ByteString)
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
decodeDNSFlags :: ByteString -> Either String DNSFlags
decodeDNSFlags bs = fst <$> runSGet getDNSFlags bs

-- | Decoding DNS header.
decodeDNSHeader :: ByteString -> Either String DNSHeader
decodeDNSHeader bs = fst <$> runSGet getHeader bs

-- | Decoding domain.
decodeDomain :: ByteString -> Either String Domain
decodeDomain bs = fst <$> runSGet getDomain bs

-- | Decoding mailbox.
decodeMailbox :: ByteString -> Either String Mailbox
decodeMailbox bs = fst <$> runSGet getMailbox bs

-- | Decoding resource record.
decodeResourceRecord :: ByteString -> Either String ResourceRecord
decodeResourceRecord bs = fst <$> runSGet getResourceRecord bs
