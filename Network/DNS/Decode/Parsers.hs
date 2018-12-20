{-# LANGUAGE BangPatterns, OverloadedStrings #-}

module Network.DNS.Decode.Parsers (
    getResponse
  , getDNSFlags
  , getHeader
  , getResourceRecord
  , getResourceRecords
  , getDomain
  , getMailbox
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BS
import qualified Data.IP
import Data.IP (IP(..), toIPv4, toIPv6b, makeAddrRange)
import Data.List (partition)

import Network.DNS.Imports
import Network.DNS.StateBinary
import Network.DNS.Types

-- $setup
-- >>> :set -XOverloadedStrings

----------------------------------------------------------------

getResponse :: SGet DNSMessage
getResponse = do
    hm <- getHeader
    qdCount <- getInt16
    anCount <- getInt16
    nsCount <- getInt16
    arCount <- getInt16
    queries <- getQueries qdCount
    answers <- getResourceRecords anCount
    authrrs <- getResourceRecords nsCount
    addnrrs <- getResourceRecords arCount
    let (opts, rest) = partition ((==) OPT. rrtype) addnrrs
        flgs         = flags hm
        rc           = fromRCODE $ rcode flgs
        (eh, erc)    = getEDNS rc opts
        hd           = hm { flags = flgs { rcode = erc } }
    pure $ DNSMessage hd eh queries answers authrrs $ ifEDNS eh rest addnrrs

  where

    -- | Get EDNS pseudo-header and the high eight bits of the extended RCODE.
    --
    getEDNS :: Word16 -> AdditionalRecords -> (EDNSheader, RCODE)
    getEDNS rc rrs = case rrs of
        [rr] | Just (edns, erc) <- optEDNS rr
               -> (EDNSheader edns, toRCODE erc)
        []     -> (NoEDNS, toRCODE rc)
        _      -> (InvalidEDNS, BadRCODE)

      where

        -- | Extract EDNS information from an OPT RR.
        --
        optEDNS :: ResourceRecord -> Maybe (EDNS, Word16)
        optEDNS (ResourceRecord "." OPT udpsiz ttl' (RD_OPT opts)) =
            let hrc      = fromIntegral rc .&. 0x0f
                erc      = shiftR (ttl' .&. 0xff000000) 20 .|. hrc
                secok    = ttl' `testBit` 15
                vers     = fromIntegral $ shiftR (ttl' .&. 0x00ff0000) 16
             in Just (EDNS vers udpsiz secok opts, fromIntegral erc)
        optEDNS _ = Nothing

----------------------------------------------------------------

getDNSFlags :: SGet DNSFlags
getDNSFlags = do
    flgs <- get16
    oc <- getOpcode flgs
    return $ DNSFlags (getQorR flgs)
                      oc
                      (getAuthAnswer flgs)
                      (getTrunCation flgs)
                      (getRecDesired flgs)
                      (getRecAvailable flgs)
                      (getRcode flgs)
                      (getAuthenData flgs)
                      (getChkDisable flgs)
  where
    getQorR w = if testBit w 15 then QR_Response else QR_Query
    getOpcode w =
        case shiftR w 11 .&. 0x0f of
            n | Just opc <- toOPCODE n
              -> pure opc
              | otherwise
              -> failSGet $ "Unsupported header opcode: " ++ show n
    getAuthAnswer w = testBit w 10
    getTrunCation w = testBit w 9
    getRecDesired w = testBit w 8
    getRecAvailable w = testBit w 7
    getRcode w = toRCODE $ w .&. 0x0f
    getAuthenData w = testBit w 5
    getChkDisable w = testBit w 4

----------------------------------------------------------------

getHeader :: SGet DNSHeader
getHeader =
    DNSHeader <$> decodeIdentifier <*> getDNSFlags
  where
    decodeIdentifier = get16

----------------------------------------------------------------

getQueries :: Int -> SGet [Question]
getQueries n = replicateM n getQuery

getTYPE :: SGet TYPE
getTYPE = toTYPE <$> get16

-- XXX: Include the class when implemented, or otherwise perhaps check the
-- implicit assumption that the class is classIN.
--
getQuery :: SGet Question
getQuery = Question <$> getDomain
                    <*> getTYPE
                    <*  ignoreClass

getResourceRecords :: Int -> SGet [ResourceRecord]
getResourceRecords n = replicateM n getResourceRecord

getResourceRecord :: SGet ResourceRecord
getResourceRecord = do
    dom <- getDomain
    typ <- getTYPE
    cls <- get16
    ttl <- get32
    len <- getInt16
    dat <- fitSGet len $ getRData typ len
    return $ ResourceRecord dom typ cls ttl dat

----------------------------------------------------------------

-- | Helper to find position of RData end, that is, the offset of the first
-- byte /after/ the current RData.
--
rdataEnd :: Int      -- ^ number of bytes left from current position
         -> SGet Int -- ^ end position
rdataEnd !len = (+) len <$> getPosition

getRData :: TYPE -> Int -> SGet RData
getRData NS _    = RD_NS    <$> getDomain
getRData MX _    = RD_MX    <$> get16 <*> getDomain
getRData CNAME _ = RD_CNAME <$> getDomain
getRData DNAME _ = RD_DNAME <$> getDomain
getRData TXT len = RD_TXT   <$> getTXT len
getRData A _     = RD_A . toIPv4 <$> getNBytes 4
getRData AAAA _  = RD_AAAA . toIPv6b <$> getNBytes 16
getRData SOA _   = RD_SOA  <$> getDomain
                           <*> getMailbox
                           <*> decodeSerial
                           <*> decodeRefesh
                           <*> decodeRetry
                           <*> decodeExpire
                           <*> decodeMinimum
  where
    decodeSerial  = get32
    decodeRefesh  = get32
    decodeRetry   = get32
    decodeExpire  = get32
    decodeMinimum = get32
getRData PTR _ = RD_PTR <$> getDomain
getRData SRV _ = RD_SRV <$> decodePriority
                        <*> decodeWeight
                        <*> decodePort
                        <*> getDomain
  where
    decodePriority = get16
    decodeWeight   = get16
    decodePort     = get16
getRData OPT len   = RD_OPT <$> getOpts len
--
getRData TLSA len = RD_TLSA <$> decodeUsage
                            <*> decodeSelector
                            <*> decodeMType
                            <*> decodeADF
  where
    decodeUsage    = get8
    decodeSelector = get8
    decodeMType    = get8
    decodeADF      = getNByteString (len - 3)
--
getRData DS len = RD_DS <$> decodeTag
                        <*> decodeAlg
                        <*> decodeDtyp
                        <*> decodeDval
  where
    decodeTag  = get16
    decodeAlg  = get8
    decodeDtyp = get8
    decodeDval = getNByteString (len - 4)
--
getRData RRSIG len = RD_RRSIG <$> decodeRRSIG
  where
    decodeRRSIG = do
        -- The signature follows a variable length zone name
        -- and occupies the rest of the RData.  Simplest to
        -- checkpoint the position at the start of the RData,
        -- and after reading the zone name, and subtract that
        -- from the RData length.
        --
        end <- rdataEnd len
        typ <- getTYPE
        alg <- get8
        cnt <- get8
        ttl <- get32
        tex <- getDnsTime
        tin <- getDnsTime
        tag <- get16
        dom <- getDomain -- XXX: Enforce no compression?
        pos <- getPosition
        val <- getNByteString $ end - pos
        return $ RDREP_RRSIG typ alg cnt ttl tex tin tag dom val
    getDnsTime   = do
        tnow <- getAtTime
        tdns <- get32
        return $! dnsTime tdns tnow
--
getRData NULL len = RD_NULL <$> getNByteString len
getRData NSEC len = do
    end <- rdataEnd len
    dom <- getDomain
    pos <- getPosition
    RD_NSEC dom <$> getNsecTypes (end - pos)
--
getRData DNSKEY len = RD_DNSKEY <$> decodeKeyFlags
                                <*> decodeKeyProto
                                <*> decodeKeyAlg
                                <*> decodeKeyBytes
  where
    decodeKeyFlags  = get16
    decodeKeyProto  = get8
    decodeKeyAlg    = get8
    decodeKeyBytes  = getNByteString (len - 4)
--
getRData NSEC3 len = do
    dend <- rdataEnd len
    halg <- get8
    flgs <- get8
    iter <- get16
    salt <- getInt8 >>= getNByteString
    hash <- getInt8 >>= getNByteString
    tpos <- getPosition
    RD_NSEC3 halg flgs iter salt hash <$> getNsecTypes (dend - tpos)
--
getRData NSEC3PARAM _ = RD_NSEC3PARAM <$> decodeHashAlg
                                      <*> decodeFlags
                                      <*> decodeIterations
                                      <*> decodeSalt
  where
    decodeHashAlg    = get8
    decodeFlags      = get8
    decodeIterations = get16
    decodeSalt       = getInt8 >>= getNByteString
--
getRData _  len = UnknownRData <$> getNByteString len

----------------------------------------------------------------

-- $
--
-- >>> import Network.DNS.StateBinary
-- >>> let Right ((t,_),l) = runSGetWithLeftovers (getTXT 8) "\3foo\3barbaz"
-- >>> (t, l) == ("foobar", "baz")
-- True

-- | Concatenate a sequence of length-prefixed strings of text
-- https://tools.ietf.org/html/rfc1035#section-3.3
--
getTXT :: Int -> SGet ByteString
getTXT !len = B.concat <$> sGetMany "TXT RR string" len getstring
  where
    getstring = getInt8 >>= getNByteString

-- <https://tools.ietf.org/html/rfc6891#section-6.1.2>
-- Parse a list of EDNS options
--
getOpts :: Int -> SGet [OData]
getOpts !len = sGetMany "EDNS option" len getoption
  where
    getoption = do
        code <- toOptCode <$> get16
        olen <- getInt16
        getOData code olen

-- <https://tools.ietf.org/html/rfc4034#section-4.1>
-- Parse a list of NSEC type bitmaps
--
getNsecTypes :: Int -> SGet [TYPE]
getNsecTypes !len = concat <$> sGetMany "NSEC type bitmap" len getbits
  where
    getbits = do
        window <- flip shiftL 8 <$> getInt8
        blocks <- getInt8
        when (blocks > 32) $
            failSGet $ "NSEC bitmap block too long: " ++ show blocks
        concatMap blkTypes. zip [window, window + 8..] <$> getNBytes blocks
      where
        blkTypes (bitOffset, byte) =
            [ toTYPE $ fromIntegral $ bitOffset + i |
              i <- [0..7], byte .&. bit (7-i) /= 0 ]

----------------------------------------------------------------

getOData :: OptCode -> Int -> SGet OData
getOData NSID len = OD_NSID <$> getNByteString len
getOData DAU  len = OD_DAU  <$> getNoctets len
getOData DHU  len = OD_DHU  <$> getNoctets len
getOData N3U  len = OD_N3U  <$> getNoctets len
getOData ClientSubnet len = do
        family  <- get16
        srcBits <- get8
        scpBits <- get8
        addrbs  <- getNByteString (len - 4) -- 4 = 2 + 1 + 1
        --
        -- https://tools.ietf.org/html/rfc7871#section-6
        --
        -- o  ADDRESS, variable number of octets, contains either an IPv4 or
        --    IPv6 address, depending on FAMILY, which MUST be truncated to the
        --    number of bits indicated by the SOURCE PREFIX-LENGTH field,
        --    padding with 0 bits to pad to the end of the last octet needed.
        --
        -- o  A server receiving an ECS option that uses either too few or too
        --    many ADDRESS octets, or that has non-zero ADDRESS bits set beyond
        --    SOURCE PREFIX-LENGTH, SHOULD return FORMERR to reject the packet,
        --    as a signal to the software developer making the request to fix
        --    their implementation.
        --
        -- In order to avoid needless decoding errors, when the ECS encoding
        -- requirements are violated, we construct an OD_ECSgeneric OData,
        -- instread of an IP-specific OD_ClientSubnet OData, which will only
        -- be used for valid inputs.  When the family is neither IPv4(1) nor
        -- IPv6(2), or the address prefix is not correctly encoded (too long
        -- or too short), the OD_ECSgeneric data contains the verbatim input
        -- from the peer.
        --
        case BS.length addrbs == (fromIntegral srcBits + 7) `div` 8 of
            True | Just ip <- bstoip family addrbs srcBits scpBits
                -> pure $ OD_ClientSubnet srcBits scpBits ip
            _   -> pure $ OD_ECSgeneric family srcBits scpBits addrbs
  where
    prefix addr bits = Data.IP.addr $ makeAddrRange addr $ fromIntegral bits
    zeropad = (++ repeat 0). map fromIntegral. B.unpack
    checkBits fromBytes toIP srcBits scpBits bytes =
        let addr       = fromBytes bytes
            maskedAddr = prefix addr srcBits
            maxBits    = fromIntegral $ 8 * length bytes
         in if addr == maskedAddr && scpBits <= maxBits
            then Just $ toIP addr
            else Nothing
    bstoip :: Word16 -> B.ByteString -> Word8 -> Word8 -> Maybe IP
    bstoip family bs srcBits scpBits = case family of
        1 -> checkBits toIPv4  IPv4 srcBits scpBits $ take 4  $ zeropad bs
        2 -> checkBits toIPv6b IPv6 srcBits scpBits $ take 16 $ zeropad bs
        _ -> Nothing
getOData opc len = UnknownOData (fromOptCode opc) <$> getNByteString len

----------------------------------------------------------------

-- | Pointers MUST point back into the packet per RFC1035 Section 4.1.4.  This
-- is further interpreted by the DNS community (from a discussion on the IETF
-- DNSOP mailing list) to mean that they don't point back into the same domain.
-- Therefore, when starting to parse a domain, the current offset is also a
-- strict upper bound on the targets of any pointers that arise while processing
-- the domain.  When following a pointer, the target again becomes a stict upper
-- bound for any subsequent pointers.  This results in a simple loop-prevention
-- algorithm, each sequence of valid pointer values is necessarily strictly
-- decreasing!  The third argument to 'getDomain'' is a strict pointer upper
-- bound, and is set here to the position at the start of parsing the domain
-- or mailbox.
--
getDomain :: SGet Domain
getDomain = getPosition >>= getDomain' '.'

getMailbox :: SGet Mailbox
getMailbox = getPosition >>= getDomain' '@'

-- $
-- Pathological case: pointer embedded inside a label!  The pointer points
-- behind the start of the domain and is then absorbed into the initial label!
-- Though we don't IMHO have to support this, it is not manifestly illegal, and
-- does exercise the code in an interesting way.  Ugly as this is, it also
-- "works" the same in Perl's Net::DNS and reportedly in ISC's BIND.
--
-- >>> :{
-- let input = "\6\3foo\192\0\3bar\0"
--     parser = skipNBytes 1 >> getDomain' '.' 1
--     Right (output, _) = runSGet parser input
--  in output == "foo.\003foo\192\000.bar."
-- :}
-- True
--
-- The case below fails to point far enough back, and triggers the loop
-- prevention code-path.
--
-- >>> :{
-- let input = "\6\3foo\192\1\3bar\0"
--     parser = skipNBytes 1 >> getDomain' '.' 1
--     Left (DecodeError err) = runSGet parser input
--  in err
-- :}
-- "invalid name compression pointer"

-- | Get a domain name, using sep1 as the separate between the 1st and 2nd
-- label.  Subsequent labels (and always the trailing label) are terminated
-- with a ".".
--
-- Domain name compression pointers must always refer to a position that
-- precedes the start of the current domain name.  The starting offsets form a
-- strictly decreasing sequence, which prevents pointer loops.
--
getDomain' :: Char -> Int -> SGet ByteString
getDomain' sep1 ptrLimit = do
    pos <- getPosition
    c <- getInt8
    let n = getValue c
    getdomain pos c n
  where
    getdomain pos c n
      | c == 0 = return "." -- Perhaps the root domain?
      | isPointer c = do
          d <- getInt8
          let offset = n * 256 + d
          when (offset >= ptrLimit) $
              failSGet "invalid name compression pointer"
          mo <- pop offset
          case mo of
              Nothing -> do
                  msg <- getInput
                  -- Reprocess the same ByteString starting at the pointer
                  -- target (offset).
                  let parser = skipNBytes offset >> getDomain' sep1 offset
                  case runSGet parser msg of
                      Left (DecodeError err) -> failSGet err
                      Left err               -> fail $ show err
                      Right o  -> push pos (fst o) >> return (fst o)
              Just o -> push pos o >> return o
      -- As for now, extended labels have no use.
      -- This may change some time in the future.
      | isExtLabel c = return ""
      | otherwise = do
          hs <- getNByteString n
          ds <- getDomain' '.' ptrLimit
          let dom = case ds of -- avoid trailing ".."
                  "." -> hs `BS.append` "."
                  _   -> hs `BS.append` BS.singleton sep1 `BS.append` ds
          push pos dom
          return dom
    getValue c = c .&. 0x3f
    isPointer c = testBit c 7 && testBit c 6
    isExtLabel c = not (testBit c 7) && testBit c 6

ignoreClass :: SGet ()
ignoreClass = () <$ get16
