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
import Data.IP (IP(..), toIPv4, toIPv6b)
import qualified Safe

import Network.DNS.Imports
import Network.DNS.StateBinary
import Network.DNS.Types

----------------------------------------------------------------

getResponse :: SGet DNSMessage
getResponse = do
    hd <- getHeader
    qdCount <- getInt16
    anCount <- getInt16
    nsCount <- getInt16
    arCount <- getInt16
    DNSMessage hd <$> getQueries qdCount
                  <*> getResourceRecords anCount
                  <*> getResourceRecords nsCount
                  <*> getResourceRecords arCount

----------------------------------------------------------------

getDNSFlags :: SGet DNSFlags
getDNSFlags = do
    word <- get16
    maybe (fail $ "Unsupported flags: 0x" ++ showHex word "") pure (toFlags word)
  where
    toFlags :: Word16 -> Maybe DNSFlags
    toFlags flgs = do
      oc <- getOpcode flgs
      let rc = getRcode flgs
      return $ DNSFlags (getQorR flgs)
                        oc
                        (getAuthAnswer flgs)
                        (getTrunCation flgs)
                        (getRecDesired flgs)
                        (getRecAvailable flgs)
                        rc
                        (getAuthenData flgs)
    getQorR w = if testBit w 15 then QR_Response else QR_Query
    getOpcode w = Safe.toEnumMay (fromIntegral (shiftR w 11 .&. 0x0f))
    getAuthAnswer w = testBit w 10
    getTrunCation w = testBit w 9
    getRecDesired w = testBit w 8
    getRecAvailable w = testBit w 7
    getRcode w = toRCODEforHeader $ fromIntegral w
    getAuthenData w = testBit w 5

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
getRData TXT len = (RD_TXT . ignoreLength) <$> getNByteString len
  where
    ignoreLength = BS.drop 1
getRData A len
  | len == 4  = (RD_A . toIPv4) <$> getNBytes len
  | otherwise = fail "IPv4 addresses must be 4 bytes long"
getRData AAAA len
  | len == 16 = (RD_AAAA . toIPv6b) <$> getNBytes len
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
        if (n == 0)
        then return B.empty
        else getNByteString n
--
getRData _  len = UnknownRData <$> getNByteString len

getOData :: OptCode -> Int -> SGet OData
getOData ClientSubnet len = do
        fam <- getInt16
        srcMask <- get8
        scpMask <- get8
        rawip <- fmap fromIntegral . B.unpack <$> getNByteString (len - 4) -- 4 = 2 + 1 + 1
        ip <- case fam of
                    1 -> pure . IPv4 . toIPv4 $ take 4 (rawip ++ repeat 0)
                    2 -> pure . IPv6 . toIPv6b $ take 16 (rawip ++ repeat 0)
                    _ -> fail "Unsupported address family"
        pure $ OD_ClientSubnet srcMask scpMask ip
getOData opc len = UnknownOData opc <$> getNByteString len

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
