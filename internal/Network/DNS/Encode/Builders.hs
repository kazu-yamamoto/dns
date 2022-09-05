{-# LANGUAGE
    BangPatterns
  , RecordWildCards
  #-}

-- | DNS Message builder.
module Network.DNS.Encode.Builders (
    putDNSMessage
  , putDNSFlags
  , putHeader
  , putDomain
  , putMailbox
  , putResourceRecord
  ) where

import Control.Monad.State (State, modify, execState)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as LBS

import Network.DNS.Imports
import Network.DNS.StateBinary
import Network.DNS.Types.Internal

----------------------------------------------------------------

putDNSMessage :: DNSMessage -> SPut
putDNSMessage msg = putHeader hd
                    <> putNums
                    <> mconcat (map putQuestion qs)
                    <> mconcat (map putResourceRecord an)
                    <> mconcat (map putResourceRecord au)
                    <> mconcat (map putResourceRecord ad)
  where
    putNums = mconcat $ fmap putInt16 [ length qs
                                      , length an
                                      , length au
                                      , length ad
                                      ]
    hm = header msg
    fl = flags hm
    eh = ednsHeader msg
    qs = question msg
    an = answer msg
    au = authority msg
    hd = ifEDNS eh hm $ hm { flags = fl { rcode = rc } }
    rc = ifEDNS eh <$> id <*> nonEDNSrcode $ rcode fl
      where
        nonEDNSrcode code | fromRCODE code < 16 = code
                          | otherwise           = FormatErr
    ad = prependOpt $ additional msg
      where
        prependOpt ads = mapEDNS eh (fromEDNS ads $ fromRCODE rc) ads
          where
            fromEDNS :: AdditionalRecords -> Word16 -> EDNS -> AdditionalRecords
            fromEDNS rrs rc' edns = ResourceRecord name' type' class' ttl' rdata' : rrs
              where
                name'  = BS.singleton '.'
                type'  = OPT
                class' = maxUdpSize `min` (minUdpSize `max` ednsUdpSize edns)
                ttl0'  = fromIntegral (rc' .&. 0xff0) `shiftL` 20
                vers'  = fromIntegral (ednsVersion edns) `shiftL` 16
                ttl'
                  | ednsDnssecOk edns = ttl0' `setBit` 15 .|. vers'
                  | otherwise         = ttl0' .|. vers'
                rdata' = RData $ RD_OPT $ ednsOptions edns

putHeader :: DNSHeader -> SPut
putHeader hdr = putIdentifier (identifier hdr)
                <> putDNSFlags (flags hdr)
  where
    putIdentifier = put16

putDNSFlags :: DNSFlags -> SPut
putDNSFlags DNSFlags{..} = put16 word
  where
    set :: Word16 -> State Word16 ()
    set byte = modify (.|. byte)

    st :: State Word16 ()
    st = sequence_
              [ set (fromRCODE rcode .&. 0x0f)
              , when chkDisable          $ set (bit 4)
              , when authenData          $ set (bit 5)
              , when recAvailable        $ set (bit 7)
              , when recDesired          $ set (bit 8)
              , when trunCation          $ set (bit 9)
              , when authAnswer          $ set (bit 10)
              , set (fromOPCODE opcode `shiftL` 11)
              , when (qOrR==QR_Response) $ set (bit 15)
              ]

    word = execState st 0

-- XXX: Use question class when implemented
--
putQuestion :: Question -> SPut
putQuestion Question{..} = putDomain qname
                           <> put16 (fromTYPE qtype)
                           <> put16 classIN

putResourceRecord :: ResourceRecord -> SPut
putResourceRecord ResourceRecord{..} = mconcat [
    putDomain rrname
  , put16 (fromTYPE rrtype)
  , put16 rrclass
  , put32 rrttl
  , putResourceRData rdata
  ]
  where
    putResourceRData :: RData -> SPut
    putResourceRData (RData rd) = do
        addPositionW 2 -- "simulate" putInt16
        rDataBuilder <- encodeResourceData rd
        let rdataLength = fromIntegral . LBS.length . BB.toLazyByteString $ rDataBuilder
        let rlenBuilder = BB.int16BE rdataLength
        return $ rlenBuilder <> rDataBuilder
