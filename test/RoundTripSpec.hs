{-# LANGUAGE OverloadedStrings, CPP #-}

module RoundTripSpec where

import Control.Monad (replicateM)
import qualified Data.IP
import Data.IP (Addr, IP(..), IPv4, IPv6, toIPv4, toIPv6, makeAddrRange)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BS
import Network.DNS.Decode
import Network.DNS.Encode
import Network.DNS.Types
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck (Gen, arbitrary, elements, forAll, frequency, listOf, oneof)
import Data.Word (Word8, Word16, Word32)
import Data.Monoid ((<>))

#if __GLASGOW_HASKELL__ < 709
import Control.Applicative
#endif


spec :: Spec
spec = do
    prop "IPv4" . forAll genIPv4 $ \ ip4 -> do
        let str = show ip4
        read str `shouldBe` ip4
        show (read str :: IPv4) `shouldBe` str

    prop "IPv6" . forAll genIPv6 $ \ ip6 -> do
        let str = show ip6
        read str `shouldBe` ip6
        show (read str :: IPv6) `shouldBe` str

    prop "TYPE" . forAll genTYPE $ \ t ->
        toTYPE (fromTYPE t) `shouldBe` t

    prop "Domain" . forAll genDomain $ \ dom -> do
        let bs = encodeDomain dom
        decodeDomain bs `shouldBe` Right dom
        fmap encodeDomain (decodeDomain bs) `shouldBe` Right bs

    prop "Mailbox" . forAll genMailbox $ \ dom -> do
        let bs = encodeMailbox dom
        decodeMailbox bs `shouldBe` Right dom
        fmap encodeMailbox (decodeMailbox bs) `shouldBe` Right bs

    prop "DNSFlags" . forAll genDNSFlags $ \ flgs -> do
        let bs = encodeDNSFlags flgs
        decodeDNSFlags bs `shouldBe` Right flgs
        fmap encodeDNSFlags (decodeDNSFlags bs) `shouldBe` Right bs

    prop "ResourceRecord" . forAll genResourceRecord $ \ rr -> do
        let bs = encodeResourceRecord rr
        decodeResourceRecord bs `shouldBe` Right rr
        fmap encodeResourceRecord (decodeResourceRecord bs) `shouldBe` Right bs

    prop "DNSHeader" . forAll genDNSHeader $ \ hdr ->
        decodeDNSHeader (encodeDNSHeader hdr) `shouldBe` Right hdr

    prop "DNSMessage" . forAll genDNSMessage $ \ msg ->
        decode (encode msg) `shouldBe` Right msg

    prop "EDNS" . forAll genEDNSHeader $ \(edns,hdr) -> do
        let rr = fromEDNS edns
            msg = DNSMessage hdr [] [] [] [rr]
            Right msg' = decode $ encode msg
            medns = toEDNS (flags hdr) (head $ additional msg')
        medns `shouldBe` Just edns

----------------------------------------------------------------

genDNSMessage :: Gen DNSMessage
genDNSMessage =
    DNSMessage <$> genDNSHeader <*> listOf genQuestion <*> listOf genResourceRecord
                <*> listOf genResourceRecord <*> listOf genResourceRecord


genQuestion :: Gen Question
genQuestion = do
    typ <- genTYPE
    dom <- genDomain
    pure $ Question dom typ

genTYPE :: Gen TYPE
genTYPE = frequency
    [ (20, elements
            [ A, AAAA, NS, TXT, MX, CNAME, SOA, PTR, SRV, DNAME, OPT, DS, RRSIG
            , NSEC, DNSKEY, NSEC3, NSEC3PARAM, TLSA, CDS, CDNSKEY, CSYNC
            ])
    , (1, toTYPE <$> genWord16)
    ]

genResourceRecord :: Gen ResourceRecord
genResourceRecord = frequency
    [ (8, genRR)
    ]
  where
    genRR = do
      dom <- genDomain
      t <- elements [A , AAAA, NS, TXT, MX, CNAME, SOA, PTR, SRV, DNAME, DS]
      ResourceRecord dom t classIN <$> genWord32 <*> mkRData dom t

mkRData :: Domain -> TYPE -> Gen RData
mkRData dom typ =
    case typ of
        A -> RD_A <$> genIPv4
        AAAA -> RD_AAAA <$> genIPv6
        NS -> pure $ RD_NS dom
        TXT -> RD_TXT <$> genByteString
        MX -> RD_MX <$> genWord16 <*> genDomain
        CNAME -> pure $ RD_CNAME dom
        SOA -> RD_SOA dom <$> genMailbox <*> genWord32 <*> genWord32 <*> genWord32 <*> genWord32 <*> genWord32
        PTR -> RD_PTR <$> genDomain
        SRV -> RD_SRV <$> genWord16 <*> genWord16 <*> genWord16 <*> genDomain
        DNAME -> RD_DNAME <$> genDomain
        DS -> RD_DS <$> genWord16 <*> genWord8 <*> genWord8 <*> genByteString
        TLSA -> RD_TLSA <$> genWord8 <*> genWord8 <*> genWord8 <*> genByteString

        _ -> pure . RD_TXT $ "Unhandled type " <> BS.pack (show typ)

genIPv4 :: Gen IPv4
genIPv4 = toIPv4 <$> replicateM 4 (fromIntegral <$> genWord8)

genIPv6 :: Gen IPv6
genIPv6 = toIPv6 <$> replicateM 8 (fromIntegral <$> genWord16)

genByteString :: Gen BS.ByteString
genByteString = elements
    [ "", "a", "a.b", "abc", "a.b.c" ]

genMboxString :: Gen BS.ByteString
genMboxString = elements
    [ "", "a", "a@b", "abc", "a@b.c" ]

genDomain :: Gen Domain
genDomain = do
    bs <- genByteString
    pure $ bs <> "."

genMailbox :: Gen Mailbox
genMailbox = do
    bs <- genMboxString
    pure $ bs <> "."

genDNSHeader :: Gen DNSHeader
genDNSHeader = DNSHeader <$> genWord16 <*> genDNSFlags

genDNSFlags :: Gen DNSFlags
genDNSFlags =
  DNSFlags <$> genQorR <*> genOPCODE <*> genBool <*> genBool
           <*> genBool <*> genBool <*> genRCODE <*> genBool <*> genBool

genWord16 :: Gen Word16
genWord16 = arbitrary

genWord32 :: Gen Word32
genWord32 = arbitrary

genWord8 :: Gen Word8
genWord8 = arbitrary

genBool :: Gen Bool
genBool = elements [True, False]

genQorR :: Gen QorR
genQorR = elements [minBound .. maxBound]

genOPCODE :: Gen OPCODE
genOPCODE  = elements [OP_STD, OP_INV, OP_SSR, OP_NOTIFY, OP_UPDATE]

genRCODE :: Gen RCODE
genRCODE = elements $ map toRCODE [0..15]

genEDNS :: Gen EDNS
genEDNS = do
    erc <- genExtRCODE
    ok <- genBool
    od <- genOData
    return $ defaultEDNS {
        extRCODE = erc
      , dnssecOk = ok
      , options  = [od]
      }

genOData :: Gen OData
genOData = oneof
    [ genOD_Unknown
    , genOD_ECS
    ]
  where
    -- | Choose from the range reserved for local use
    -- https://tools.ietf.org/html/rfc6891#section-9
    genOD_Unknown = do
      opc <- elements [65001, 65534]
      bs <- genByteString
      pure $ UnknownOData opc bs

    -- | Only valid ECS prefixes round-trip, make sure the prefix is
    -- is consistent with the mask.
    genOD_ECS = do
        usev4 <- genBool
        if usev4
        then genFuzzed genIPv4 IPv4 Data.IP.fromIPv4  1 32
        else genFuzzed genIPv6 IPv6 Data.IP.fromIPv6b 2 128
      where
        genFuzzed :: Addr a
                  => Gen a
                  -> (a -> IP)
                  -> (a -> [Int])
                  -> Word16
                  -> Word8
                  -> Gen OData
        genFuzzed gen toIP toBytes fam alen = do
            ip <- gen
            bits1 <- elements [1 .. alen]
            bits2 <- elements [0 .. alen]
            fuzzSrcBits <- genBool
            fuzzScpBits <- genBool
            srcBits <- if not fuzzSrcBits
                       then pure bits1
                       else flip mod alen. (+) bits1 <$> elements [1..alen-1]
            scpBits <- if not fuzzScpBits
                       then pure bits2
                       else elements [alen+1 .. 0xFF]
            let addr  = Data.IP.addr. makeAddrRange ip $ fromIntegral bits1
                bytes = map fromIntegral $ toBytes addr
                len   = (fromIntegral bits1 + 7) `div` 8
                less  = take (len - 1) bytes
                more  = less ++ [0xFF]
            if srcBits == bits1
            then if scpBits == bits2
                 then pure $ OD_ClientSubnet bits1 scpBits $ toIP addr
                 else pure $ OD_ECSgeneric fam bits1 scpBits $ B.pack bytes
            else if (srcBits < bits1)
                 then pure $ OD_ECSgeneric fam srcBits scpBits $ B.pack more
                 else pure $ OD_ECSgeneric fam srcBits scpBits $ B.pack less

genExtRCODE :: Gen RCODE
genExtRCODE = elements $ map toRCODE [0..4095]

genEDNSHeader :: Gen (EDNS, DNSHeader)
genEDNSHeader = do
    edns <- genEDNS
    hdr <- genDNSHeader
    let flg = flags hdr
    return (edns, hdr { flags =  flg { rcode = extRCODE edns } })
