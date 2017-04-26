{-# LANGUAGE OverloadedStrings, DeriveDataTypeable, CPP #-}

module Network.DNS.Decode (
    decode
  , decodeDomain
  , decodeDNSFlags
  , decodeDNSHeader
  , decodeResourceRecord
  , decodeMany
  , receive
  , receiveVC
  ) where

import Control.Applicative (many)
import Control.Monad (replicateM)
import Control.Monad.Trans.Resource (ResourceT, runResourceT)
import qualified Control.Exception as ControlException
import Data.Bits ((.&.), shiftR, testBit)
import Data.Char (ord)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.Conduit (($$), ($$+), ($$+-), (=$), Source)
import Data.Conduit.Network (sourceSocket)
import qualified Data.Conduit.Binary as CB
import Data.IP (IP(..), toIPv4, toIPv6b)
import Data.Typeable (Typeable)
import Data.Word (Word16)
import Network (Socket)
import Network.DNS.Internal
import Network.DNS.StateBinary
import Numeric (showHex)
import qualified Safe

#if __GLASGOW_HASKELL__ < 709
import Control.Applicative
#endif

----------------------------------------------------------------


data RDATAParseError = RDATAParseError String
 deriving (Show, Typeable)

instance ControlException.Exception RDATAParseError


-- | Receiving DNS data from 'Socket' and parse it.

receive :: Socket -> IO DNSMessage
receive = receiveDNSFormat . sourceSocket

-- | Receive and parse a single virtual-circuit (TCP) response.  It
--   is up to the caller to implement any desired timeout.  This
--   (and the other response decoding functions) may throw ParseError
--   when the server response is incomplete or malformed.

receiveVC :: Socket -> IO DNSMessage
receiveVC sock = runResourceT $ do
    (src, lenbytes) <- sourceSocket sock $$+ CB.take 2
    let len = case map ord $ LBS.unpack lenbytes of
                [hi, lo] -> 256 * hi + lo
                _        -> 0
    fmap fst (src $$+- CB.isolate len =$ sinkSGet getResponse)

----------------------------------------------------------------

-- | Parsing DNS data.

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

decodeDNSFlags :: ByteString -> Either String DNSFlags
decodeDNSFlags bs = fst <$> runSGet getDNSFlags bs

decodeDNSHeader :: ByteString -> Either String DNSHeader
decodeDNSHeader bs = fst <$> runSGet getHeader bs

decodeDomain :: ByteString -> Either String Domain
decodeDomain bs = fst <$> runSGet getDomain bs

decodeResourceRecord :: ByteString -> Either String ResourceRecord
decodeResourceRecord bs = fst <$> runSGet getResourceRecord bs

----------------------------------------------------------------
receiveDNSFormat :: Source (ResourceT IO) ByteString -> IO DNSMessage
receiveDNSFormat src = fst <$> runResourceT (src $$ sink)
  where
    sink = sinkSGet getResponse

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
      rc <- getRcode flgs
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
    getRcode w = Safe.toEnumMay (fromIntegral (w .&. 0x0f))
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
getTYPE = intToType <$> get16

getOptType :: SGet OPTTYPE
getOptType = intToOptType <$> getInt16

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
    getRR dom typ
  where
    getRR _ OPT = do
        udps <- decodeUDPSize -- 16
        _ <- decodeERCode    -- 8
        ver <- decodeOPTVer  -- 8
        dok <- decodeDNSOK   -- 16
        len <- decodeRLen    -- 16
        dat <- getRData OPT len
        return $ OptRecord udps dok ver dat

    getRR dom t = do
        ignoreClass
        ttl <- decodeTTL
        len <- decodeRLen
        dat <- getRData t len
        return $ ResourceRecord dom t ttl dat

    decodeUDPSize = get16
    decodeERCode = get8
    decodeOPTVer = get8
    decodeDNSOK = flip testBit 15 <$> get16
    decodeTTL = get32
    decodeRLen = getInt16

getRData :: TYPE -> Int -> SGet RData
getRData NS _ = RD_NS <$> getDomain
getRData MX _ = RD_MX <$> decodePreference <*> getDomain
  where
    decodePreference = get16
getRData CNAME _ = RD_CNAME <$> getDomain
getRData DNAME _ = RD_DNAME <$> getDomain
getRData TXT len = (RD_TXT . ignoreLength) <$> getNByteString len
  where
    ignoreLength = BS.tail
getRData A len
  | len == 4  = (RD_A . toIPv4) <$> getNBytes len
  | otherwise = fail "IPv4 addresses must be 4 bytes long"
getRData AAAA len
  | len == 16 = (RD_AAAA . toIPv6b) <$> getNBytes len
  | otherwise = fail "IPv6 addresses must be 16 bytes long"
getRData SOA _ = RD_SOA <$> getDomain
                           <*> getDomain
                           <*> decodeSerial
                           <*> decodeRefesh
                           <*> decodeRetry
                           <*> decodeExpire
                           <*> decodeMinumun
  where
    decodeSerial  = get32
    decodeRefesh  = get32
    decodeRetry   = get32
    decodeExpire  = get32
    decodeMinumun = get32
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
            optCode <- getOptType
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
getRData _  len = RD_OTH <$> getNByteString len

getOData :: OPTTYPE -> Int -> SGet OData
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
getOData (OUNKNOWN i) len = OD_Unknown i <$> getNByteString len

----------------------------------------------------------------

getDomain :: SGet Domain
getDomain = do
    pos <- getPosition
    c <- getInt8
    let n = getValue c
    -- Syntax hack to avoid using MultiWayIf
    case () of
        _ | c == 0 -> return "." -- Perhaps the root domain?
        _ | isPointer c -> do
            d <- getInt8
            let offset = n * 256 + d
            mo <- pop offset
            case mo of
                Nothing -> fail $ "getDomain: " ++ show offset
                -- A pointer may refer to another pointer.
                -- So, register this position for the domain.
                Just o -> push pos o >> return o
        -- As for now, extended labels have no use.
        -- This may change some time in the future.
        _ | isExtLabel c -> return ""
        _ -> do
            hs <- getNByteString n
            ds <- getDomain
            let dom =
                    case ds of -- avoid trailing ".."
                        "." -> hs `BS.append` "."
                        _   -> hs `BS.append` "." `BS.append` ds
            push pos dom
            return dom
  where
    getValue c = c .&. 0x3f
    isPointer c = testBit c 7 && testBit c 6
    isExtLabel c = not (testBit c 7) && testBit c 6

ignoreClass :: SGet ()
ignoreClass = () <$ get16
