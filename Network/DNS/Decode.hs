{-# LANGUAGE OverloadedStrings #-}

module Network.DNS.Decode (
    decode
  , receive
  ) where

import Control.Applicative ((<$), (<$>), (<*), (<*>))
import Control.Monad (replicateM)
import Control.Monad.Trans.Resource (ResourceT, runResourceT)
import Data.Bits ((.&.), shiftR, testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as BL
import Data.Conduit (($$), Source)
import Data.Conduit.Network (sourceSocket)
import Data.IP (toIPv4, toIPv6)
import Network (Socket)
import Network.DNS.Internal
import Network.DNS.StateBinary

----------------------------------------------------------------

-- | Receiving DNS data from 'Socket' and parse it.

receive :: Socket -> IO DNSFormat
receive sock = receiveDNSFormat $ sourceSocket sock

----------------------------------------------------------------

-- | Parsing DNS data.

decode :: BL.ByteString -> Either String DNSFormat
decode bs = fst <$> runSGet decodeResponse bs

----------------------------------------------------------------
receiveDNSFormat :: Source (ResourceT IO) ByteString -> IO DNSFormat
receiveDNSFormat src = fst <$> runResourceT (src $$ sink)
  where
    sink = sinkSGet decodeResponse

----------------------------------------------------------------

decodeResponse :: SGet DNSFormat
decodeResponse = do
    hd <- decodeHeader
    DNSFormat hd <$> decodeQueries (qdCount hd)
                 <*> decodeRRs (anCount hd)
                 <*> decodeRRs (nsCount hd)
                 <*> decodeRRs (arCount hd)

----------------------------------------------------------------

decodeFlags :: SGet DNSFlags
decodeFlags = toFlags <$> get16
  where
    toFlags flgs = DNSFlags (getQorR flgs)
                            (getOpcode flgs)
                            (getAuthAnswer flgs)
                            (getTrunCation flgs)
                            (getRecDesired flgs)
                            (getRecAvailable flgs)
                            (getRcode flgs)
    getQorR w = if testBit w 15 then QR_Response else QR_Query
    getOpcode w = toEnum $ fromIntegral $ shiftR w 11 .&. 0x0f
    getAuthAnswer w = testBit w 10
    getTrunCation w = testBit w 9
    getRecDesired w = testBit w 8
    getRecAvailable w = testBit w 7
    getRcode w = toEnum $ fromIntegral $ w .&. 0x0f

----------------------------------------------------------------

decodeHeader :: SGet DNSHeader
decodeHeader = DNSHeader <$> decodeIdentifier
                         <*> decodeFlags
                         <*> decodeQdCount
                         <*> decodeAnCount
                         <*> decodeNsCount
                         <*> decodeArCount
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

decodeQuery :: SGet Question
decodeQuery = Question <$> decodeDomain
                       <*> (decodeType <* ignoreClass)

decodeRRs :: Int -> SGet [ResourceRecord]
decodeRRs n = replicateM n decodeRR

decodeRR :: SGet ResourceRecord
decodeRR = do
    Question dom typ <- decodeQuery
    ttl <- decodeTTL
    len <- decodeRLen
    dat <- decodeRData typ len
    return ResourceRecord { rrname = dom
                          , rrtype = typ
                          , rrttl  = ttl
                          , rdlen  = len
                          , rdata  = dat
                          }
  where
    decodeTTL = fromIntegral <$> get32
    decodeRLen = getInt16

decodeRData :: TYPE -> Int -> SGet RDATA
decodeRData NS _ = RD_NS <$> decodeDomain
decodeRData MX _ = RD_MX <$> decodePreference <*> decodeDomain
  where
    decodePreference = getInt16
decodeRData CNAME _ = RD_CNAME <$> decodeDomain
decodeRData TXT len = (RD_TXT . ignoreLength) <$> getNByteString len
  where
    ignoreLength = BS.tail
decodeRData A len  = (RD_A . toIPv4) <$> getNBytes len
decodeRData AAAA len  = (RD_AAAA . toIPv6 . combine) <$> getNBytes len
  where
    combine [] = []
    combine [_] = fail "combine"
    combine (a:b:cs) =  a * 256 + b : combine cs
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

decodeRData _  len = RD_OTH <$> getNBytes len

----------------------------------------------------------------

decodeDomain :: SGet Domain
decodeDomain = do
    pos <- getPosition
    c <- getInt8
    if c == 0 then
        return ""
      else do
        let n = getValue c
        if isPointer c then do
            d <- getInt8
            let offset = n * 256 + d
            mo <- pop offset
            case mo of
                Nothing -> fail $ "decodeDomain: " ++ show offset
                Just o -> return o
          else do
            hs <- getNByteString n
            ds <- decodeDomain
            let dom = hs `BS.append` "." `BS.append` ds
            push pos dom
            return dom
  where
    getValue c = c .&. 0x3f
    isPointer c = testBit c 7 && testBit c 6

ignoreClass :: SGet ()
ignoreClass = () <$ get16
