{-# LANGUAGE OverloadedStrings #-}

module Network.DNS.Decode.Parsers (
    getResponse
  , getDNSFlags
  , getHeader
  , getResourceRecord
  , getResourceRecords
  , getDomain
  , getMailbox
  ) where

import Network.DNS.Imports
import Network.DNS.StateBinary
import Network.DNS.Types.Internal

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
        optEDNS (ResourceRecord "." OPT udpsiz ttl' rd) = case fromRData rd of
            Just (RD_OPT opts) ->
                let hrc      = fromIntegral rc .&. 0x0f
                    erc      = shiftR (ttl' .&. 0xff000000) 20 .|. hrc
                    secok    = ttl' `testBit` 15
                    vers     = fromIntegral $ shiftR (ttl' .&. 0x00ff0000) 16
                in Just (EDNS vers udpsiz secok opts, fromIntegral erc)
            _ -> Nothing
        optEDNS _ = Nothing

----------------------------------------------------------------

getDNSFlags :: SGet DNSFlags
getDNSFlags = do
    flgs <- get16
    let oc = getOpcode flgs
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

-- XXX: Include the class when implemented, or otherwise perhaps check the
-- implicit assumption that the class is classIN.
--
getQuery :: SGet Question
getQuery = Question <$> getDomain
                    <*> getTYPE
                    <*  ignoreClass
  where
    ignoreClass = get16

getResourceRecords :: Int -> SGet [ResourceRecord]
getResourceRecords n = replicateM n getResourceRecord

getResourceRecord :: SGet ResourceRecord
getResourceRecord = do
    dom <- getDomain
    typ <- getTYPE
    cls <- get16
    ttl <- get32
    len <- getInt16
    dat <- fitSGet len $ switch typ len
    return $ ResourceRecord dom typ cls ttl dat

-- fixme
switch :: TYPE -> Int -> SGet RData
switch A     l = toRData <$> decodeResourceData (Proxy :: Proxy RD_A)     l
switch NS    l = toRData <$> decodeResourceData (Proxy :: Proxy RD_NS)    l
switch CNAME l = toRData <$> decodeResourceData (Proxy :: Proxy RD_CNAME) l
switch SOA   l = toRData <$> decodeResourceData (Proxy :: Proxy RD_SOA)   l
switch NULL  l = toRData <$> decodeResourceData (Proxy :: Proxy RD_NULL)  l
switch PTR   l = toRData <$> decodeResourceData (Proxy :: Proxy RD_PTR)   l
switch MX    l = toRData <$> decodeResourceData (Proxy :: Proxy RD_MX)    l
switch TXT   l = toRData <$> decodeResourceData (Proxy :: Proxy RD_TXT)   l
switch RP    l = toRData <$> decodeResourceData (Proxy :: Proxy RD_RP)    l
switch AAAA  l = toRData <$> decodeResourceData (Proxy :: Proxy RD_AAAA)  l
switch SRV   l = toRData <$> decodeResourceData (Proxy :: Proxy RD_SRV)   l
switch DNAME l = toRData <$> decodeResourceData (Proxy :: Proxy RD_DNAME) l
switch OPT   l = toRData <$> decodeResourceData (Proxy :: Proxy RD_OPT)   l
switch DS    l = toRData <$> decodeResourceData (Proxy :: Proxy RD_DS)    l
switch RRSIG l = toRData <$> decodeResourceData (Proxy :: Proxy RD_RRSIG) l
switch NSEC  l = toRData <$> decodeResourceData (Proxy :: Proxy RD_NSEC)  l
switch DNSKEY l = toRData <$> decodeResourceData (Proxy :: Proxy RD_DNSKEY) l
switch NSEC3 l = toRData <$> decodeResourceData (Proxy :: Proxy RD_NSEC3) l
switch NSEC3PARAM l = toRData <$> decodeResourceData (Proxy :: Proxy RD_NSEC3PARAM)     l
switch TLSA  l = toRData <$> decodeResourceData (Proxy :: Proxy RD_TLSA)  l
switch CDS   l = toRData <$> decodeResourceData (Proxy :: Proxy RD_CDS)   l
switch CDNSKEY l = toRData <$> decodeResourceData (Proxy :: Proxy RD_CDNSKEY) l
switch typ   l = toRData <$> RD_Unknown typ <$> getNByteString l
