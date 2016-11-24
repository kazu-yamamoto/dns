{-# LANGUAGE OverloadedStrings, DeriveDataTypeable, CPP #-}

module Network.DNS.Decode (
    decode
  , decodeMany
  , receive
  , receiveVC
  ) where

import Control.Applicative (many)
import Control.Monad (replicateM)
import Control.Monad.Trans.Resource (ResourceT, runResourceT)
import qualified Control.Exception as ControlException
import Data.Bits ((.&.), shiftR, testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as BL
import Data.Conduit (($$), ($$+), ($$+-), (=$), Source)
import Data.Conduit.Network (sourceSocket)
import qualified Data.Conduit.Binary as CB
import Data.IP (IP(..), toIPv4, toIPv6b)
import Data.Typeable (Typeable)
import Data.Word (Word16)
import Network (Socket)
import Network.DNS.Internal
import Network.DNS.StateBinary
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
    let len = case (map fromIntegral $ BL.unpack lenbytes) of
                hi:lo:[] -> 256 * hi + lo
                _        -> 0
    src $$+- CB.isolate len =$ sinkSGet decodeResponse >>= return . fst

----------------------------------------------------------------

-- | Parsing DNS data.

decode :: BL.ByteString -> Either String DNSMessage
decode bs = fst <$> runSGet decodeResponse bs

-- | Parse many length-encoded DNS records, for example, from TCP traffic.

decodeMany :: BL.ByteString -> Either String ([DNSMessage], BL.ByteString)
decodeMany bs = do
    ((bss, _), leftovers) <- runSGetWithLeftovers lengthEncoded bs
    msgs <- mapM decode bss
    return (msgs, leftovers)
  where
    -- Read a list of length-encoded lazy bytestrings
    lengthEncoded :: SGet [BL.ByteString]
    lengthEncoded = many $ do
      len <- getInt16
      fmap BL.fromStrict (getNByteString len)

----------------------------------------------------------------
receiveDNSFormat :: Source (ResourceT IO) ByteString -> IO DNSMessage
receiveDNSFormat src = fst <$> runResourceT (src $$ sink)
  where
    sink = sinkSGet decodeResponse

----------------------------------------------------------------

decodeResponse :: SGet DNSMessage
decodeResponse = do
    (hd,qdCount,anCount,nsCount,arCount) <- decodeHeader
    DNSMessage hd <$> decodeQueries qdCount
                  <*> decodeRRs anCount
                  <*> decodeRRs nsCount
                  <*> decodeRRs arCount

----------------------------------------------------------------

decodeFlags :: SGet DNSFlags
decodeFlags = do
    word <- get16
    maybe (fail "Unsupported flags") pure (toFlags word)
  where
    toFlags :: Word16 -> Maybe DNSFlags
    toFlags flgs = do
      opcode_ <- getOpcode flgs
      rcode_ <- getRcode flgs
      return $ DNSFlags (getQorR flgs)
                        opcode_
                        (getAuthAnswer flgs)
                        (getTrunCation flgs)
                        (getRecDesired flgs)
                        (getRecAvailable flgs)
                        rcode_
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

decodeHeader :: SGet (DNSHeader,Int,Int,Int,Int)
decodeHeader = do
        hd <- DNSHeader <$> decodeIdentifier
                        <*> decodeFlags
        qdCount <- decodeQdCount
        anCount <- decodeAnCount
        nsCount <- decodeNsCount
        arCount <- decodeArCount
        pure (hd
             ,qdCount
             ,anCount
             ,nsCount
             ,arCount
             )
  where
    decodeIdentifier = getInt16
    decodeQdCount = getInt16
    decodeAnCount = getInt16
    decodeNsCount = getInt16
    decodeArCount = getInt16

----------------------------------------------------------------

decodeQueries :: Int -> SGet [Question]
decodeQueries n = replicateM n decodeQuery

decodeType :: SGet TYPE
decodeType = intToType <$> getInt16

decodeOptType :: SGet OPTTYPE
decodeOptType = intToOptType <$> getInt16

decodeQuery :: SGet Question
decodeQuery = Question <$> decodeDomain
                       <*> decodeType
                       <*  ignoreClass

decodeRRs :: Int -> SGet [ResourceRecord]
decodeRRs n = replicateM n decodeRR

decodeRR :: SGet ResourceRecord
decodeRR = do
    dom <- decodeDomain
    typ <- decodeType
    decodeRR' dom typ
  where
    decodeRR' _ OPT = do
        udps <- decodeUDPSize
        _ <- decodeERCode
        ver <- decodeOPTVer
        dok <- decodeDNSOK
        len <- decodeRLen
        dat <- decodeRData OPT len
        return OptRecord { orudpsize = udps
                         , ordnssecok = dok
                         , orversion = ver
                         , rdata = dat
                         }

    decodeRR' dom t = do
        ignoreClass
        ttl <- decodeTTL
        len <- decodeRLen
        dat <- decodeRData t len
        return ResourceRecord { rrname = dom
                              , rrtype = t
                              , rrttl  = ttl
                              , rdata  = dat
                              }
    decodeUDPSize = fromIntegral <$> getInt16
    decodeERCode = getInt8
    decodeOPTVer = fromIntegral <$> getInt8
    decodeDNSOK = flip testBit 15 <$> getInt16
    decodeTTL = fromIntegral <$> get32
    decodeRLen = getInt16

decodeRData :: TYPE -> Int -> SGet RData
decodeRData NS _ = RD_NS <$> decodeDomain
decodeRData MX _ = RD_MX <$> decodePreference <*> decodeDomain
  where
    decodePreference = getInt16
decodeRData CNAME _ = RD_CNAME <$> decodeDomain
decodeRData DNAME _ = RD_DNAME <$> decodeDomain
decodeRData TXT len = (RD_TXT . ignoreLength) <$> getNByteString len
  where
    ignoreLength = BS.tail
decodeRData A len
  | len == 4  = (RD_A . toIPv4) <$> getNBytes len
  | otherwise = fail "IPv4 addresses must be 4 bytes long"
decodeRData AAAA len
  | len == 16 = (RD_AAAA . toIPv6b) <$> getNBytes len
  | otherwise = fail "IPv6 addresses must be 16 bytes long"
decodeRData SOA _ = RD_SOA <$> decodeDomain
                           <*> decodeDomain
                           <*> decodeSerial
                           <*> decodeRefesh
                           <*> decodeRetry
                           <*> decodeExpire
                           <*> decodeMinumun
  where
    decodeSerial  = getInt32
    decodeRefesh  = getInt32
    decodeRetry   = getInt32
    decodeExpire  = getInt32
    decodeMinumun = getInt32
decodeRData PTR _ = RD_PTR <$> decodeDomain
decodeRData SRV _ = RD_SRV <$> decodePriority
                           <*> decodeWeight
                           <*> decodePort
                           <*> decodeDomain
  where
    decodePriority = getInt16
    decodeWeight   = getInt16
    decodePort     = getInt16
decodeRData OPT ol = RD_OPT <$> decode' ol
  where
    decode' :: Int -> SGet [OData]
    decode' l
        | l  < 0 = fail "decodeOPTData: length inconsistency"
        | l == 0 = pure []
        | otherwise = do
            optCode <- decodeOptType
            optLen <- getInt16
            dat <- decodeOData optCode optLen
            (dat:) <$> decode' (l - optLen - 4)
--
decodeRData TLSA len = RD_TLSA <$> decodeUsage
                               <*> decodeSelector
                               <*> decodeMType
                               <*> decodeADF
  where
    decodeUsage    = get8
    decodeSelector = get8
    decodeMType    = get8
    decodeADF      = getNByteString (len - 3)
decodeRData _  len = RD_OTH <$> getNByteString len

decodeOData :: OPTTYPE -> Int -> SGet OData
decodeOData ClientSubnet len = do
        fam <- getInt16
        srcMask <- getInt8
        scpMask <- getInt8
        rawip <- fmap fromIntegral . B.unpack <$> getNByteString (len - 4) -- 4 = 2 + 1 + 1
        ip <- case fam of
                    1 -> pure . IPv4 . toIPv4 $ take 4 (rawip ++ repeat 0)
                    2 -> pure . IPv6 . toIPv6b $ take 16 (rawip ++ repeat 0)
                    _ -> fail "Unsupported address family"
        pure $ OD_ClientSubnet srcMask scpMask ip
decodeOData (OUNKNOWN i) len = OD_Unknown i <$> getNByteString len

----------------------------------------------------------------

decodeDomain :: SGet Domain
decodeDomain = do
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
                Nothing -> fail $ "decodeDomain: " ++ show offset
                -- A pointer may refer to another pointer.
                -- So, register this position for the domain.
                Just o -> push pos o >> return o
        -- As for now, extended labels have no use.
        -- This may change some time in the future.
        _ | isExtLabel c -> return ""
        _ | otherwise -> do
            hs <- getNByteString n
            ds <- decodeDomain
            let dom =
                    case ds of -- avoid trailing ".."
                        "." -> hs `BS.append` "."
                        _   -> hs `BS.append` "." `BS.append` ds
            push pos dom
            return dom
  where
    getValue c = c .&. 0x3f
    isPointer c = testBit c 7 && testBit c 6
    isExtLabel c = (not $ testBit c 7) && testBit c 6

ignoreClass :: SGet ()
ignoreClass = () <$ get16
