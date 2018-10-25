{-# LANGUAGE OverloadedStrings #-}

module Network.DNS.Decode.Internal (
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
    word <- get16
    maybe (fail $ "Unsupported flags: 0x" ++ showHex word "") pure (toFlags word)
  where
    toFlags :: Word16 -> Maybe DNSFlags
    toFlags flgs = do
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
    getQorR w = if testBit w 15 then QR_Response else QR_Query
    getOpcode w = toOPCODE (shiftR w 11 .&. 0x0f)
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

getOptCode :: SGet OptCode
getOptCode = toOptCode <$> get16

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
    cls <- decodeCLASS
    ttl <- decodeTTL
    len <- decodeRLen
    dat <- getRData typ len
    return $ ResourceRecord dom typ cls ttl dat
  where
    decodeCLASS = get16
    decodeTTL   = get32
    decodeRLen  = getInt16

getRData :: TYPE -> Int -> SGet RData
getRData NS _ = RD_NS <$> getDomain
getRData MX _ = RD_MX <$> decodePreference <*> getDomain
  where
    decodePreference = get16
getRData CNAME _ = RD_CNAME <$> getDomain
getRData DNAME _ = RD_DNAME <$> getDomain
getRData TXT len = RD_TXT . ignoreLength <$> getNByteString len
  where
    ignoreLength = BS.drop 1
getRData A len
  | len == 4  = RD_A . toIPv4 <$> getNBytes len
  | otherwise = fail "IPv4 addresses must be 4 bytes long"
getRData AAAA len
  | len == 16 = RD_AAAA . toIPv6b <$> getNBytes len
  | otherwise = fail "IPv6 addresses must be 16 bytes long"
getRData SOA _ = RD_SOA    <$> getDomain
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
getRData OPT ol = RD_OPT <$> decode' ol
  where
    decode' :: Int -> SGet [OData]
    decode' l
        | l  < 0 = fail $ "decodeOPTData: length inconsistency (" ++ show l ++ ")"
        | l == 0 = pure []
        | otherwise = do
            optCode <- getOptCode
            optLen <- getInt16
            dat <- getOData optCode optLen
            (dat:) <$> decode' (l - optLen - 4)
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
        pos0 <- getPosition
        typ <- getTYPE
        alg <- get8
        cnt <- get8
        ttl <- get32
        tex <- getDnsTime
        tin <- getDnsTime
        tag <- get16
        dom <- getDomain -- XXX: Enforce no compression?
        pos1 <- getPosition
        val <- getNByteString (len - (pos1 - pos0))
        return $ RDREP_RRSIG typ alg cnt ttl tex tin tag dom val
    getDnsTime   = do
        tnow <- getAtTime
        tdns <- get32
        return $! dnsTime tdns tnow
--
getRData NULL len = const RD_NULL <$> getNByteString len
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
getRData NSEC3PARAM len = RD_NSEC3PARAM <$> decodeHashAlg
                                <*> decodeFlags
                                <*> decodeIterations
                                <*> decodeSalt
  where
    decodeHashAlg    = get8
    decodeFlags      = get8
    decodeIterations = get16
    decodeSalt       = do
        let n = len - 5
        slen <- get8
        guard $ fromIntegral slen == n
        if n == 0
        then return B.empty
        else getNByteString n
--
getRData _  len = UnknownRData <$> getNByteString len

getOData :: OptCode -> Int -> SGet OData
getOData NSID len = OD_NSID          <$> getNByteString len
getOData DAU  len = OD_DAU. B.unpack <$> getNByteString len
getOData DHU  len = OD_DHU. B.unpack <$> getNByteString len
getOData N3U  len = OD_N3U. B.unpack <$> getNByteString len
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

getDomain :: SGet Domain
getDomain = do
    lim <- B.length <$> getInput
    getDomain' '.' lim 0

getMailbox :: SGet Mailbox
getMailbox = do
    lim <- B.length <$> getInput
    getDomain' '@' lim 0

-- | Get a domain name, using sep1 as the separate between the 1st and 2nd
-- label.  Subsequent labels (and always the trailing label) are terminated
-- with a ".".
getDomain' :: Char -> Int -> Int -> SGet ByteString
getDomain' sep1 lim loopcnt
  -- 127 is the logical limitation of pointers.
  | loopcnt >= 127 = fail "pointer recursion limit exceeded"
  | otherwise      = do
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
          when (offset >= lim) $ fail "pointer is too large"
          mo <- pop offset
          case mo of
              Nothing -> do
                  target <- B.drop offset <$> getInput
                  case runSGet (getDomain' sep1 lim (loopcnt + 1)) target of
                        Left (DecodeError err) -> fail err
                        Left err               -> fail $ show err
                        Right o  -> push pos (fst o) >> return (fst o)
              Just o -> push pos o >> return o
      -- As for now, extended labels have no use.
      -- This may change some time in the future.
      | isExtLabel c = return ""
      | otherwise = do
          hs <- getNByteString n
          ds <- getDomain' '.' lim (loopcnt + 1)
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
