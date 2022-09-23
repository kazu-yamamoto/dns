{-# LANGUAGE OverloadedStrings, TransformListComp #-}

module RoundTripSpec where

import qualified Data.IP
import Data.IP (Addr, IP(..), IPv4, IPv6, toIPv4, toIPv6, makeAddrRange)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BS
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck (Gen, arbitrary, elements, forAll, frequency, listOf, oneof)
import GHC.Exts (the, groupWith)

import Network.DNS.Decode
import Network.DNS.Decode.Internal
import Network.DNS.Encode
import Network.DNS.Encode.Internal
import Network.DNS.Imports
import Network.DNS.Types

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

    prop "DNSFlags" . forAll (genDNSFlags 0x0f) $ \ flgs -> do
        let bs = encodeDNSFlags flgs
        decodeDNSFlags bs `shouldBe` Right flgs
        fmap encodeDNSFlags (decodeDNSFlags bs) `shouldBe` Right bs

    prop "ResourceRecord" . forAll genResourceRecord $ \ rr -> do
        let bs = encodeResourceRecord rr
        decodeResourceRecord bs `shouldBe` Right rr
        fmap encodeResourceRecord (decodeResourceRecord bs) `shouldBe` Right bs

    prop "DNSHeader" . forAll (genDNSHeader 0x0f) $ \ hdr ->
        decodeDNSHeader (encodeDNSHeader hdr) `shouldBe` Right hdr

    prop "DNSMessage" . forAll genDNSMessage $ \ msg ->
        decode (encode msg) `shouldBe` Right msg

    prop "EDNS" . forAll genEDNSHeader $ \(edns, hdr) -> do
        let eh = EDNSheader edns
            Right m = decode. encode $ DNSMessage hdr eh [] [] [] []
        ednsHeader m `shouldBe` eh

----------------------------------------------------------------

genDNSMessage :: Gen DNSMessage
genDNSMessage =
    DNSMessage <$> genDNSHeader 0x0f <*> makeEDNS <*> listOf genQuestion
               <*> listOf genResourceRecord  <*> listOf genResourceRecord
               <*> listOf genResourceRecord
  where
    makeEDNS :: Gen EDNSheader
    makeEDNS = genBool >>= \t ->
        if t then EDNSheader <$> genEDNS
             else pure NoEDNS


genQuestion :: Gen Question
genQuestion = Question <$> genDomain <*> genTYPE

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
      t <- elements [A, AAAA, NS, TXT, MX, CNAME, SOA, PTR, SRV, DNAME, DS,
                     TLSA, NSEC, NSEC3]
      ResourceRecord dom t classIN <$> genWord32 <*> mkRData dom t

mkRData :: Domain -> TYPE -> Gen RData
mkRData dom typ =
    case typ of
        A -> RD_A <$> genIPv4
        AAAA -> RD_AAAA <$> genIPv6
        NS -> pure $ RD_NS dom
        TXT -> RD_TXT <$> genTextString
        MX -> RD_MX <$> genWord16 <*> genDomain
        CNAME -> pure $ RD_CNAME dom
        SOA -> RD_SOA dom <$> genMailbox <*> genWord32 <*> genWord32 <*> genWord32 <*> genWord32 <*> genWord32
        PTR -> RD_PTR <$> genDomain
        SRV -> RD_SRV <$> genWord16 <*> genWord16 <*> genWord16 <*> genDomain
        DNAME -> RD_DNAME <$> genDomain
        DS -> RD_DS <$> genWord16 <*> genWord8 <*> genWord8 <*> genByteString
        NSEC -> RD_NSEC <$> genDomain <*> genNsecTypes
        NSEC3 -> genNSEC3
        TLSA -> RD_TLSA <$> genWord8 <*> genWord8 <*> genWord8 <*> genByteString
        CAA -> RD_CAA <$> genWord8 <*> genByteString <*> genByteString

        _ -> pure . RD_TXT $ "Unhandled type " <> BS.pack (show typ)
  where
    genNSEC3 = do
        (alg, hlen)  <- elements [(1,32),(2,64)]
        flgs <- elements [0,1]
        iter <- elements [0..100]
        salt <- elements ["", "AB"]
        hash <- B.pack <$> replicateM hlen genWord8
        RD_NSEC3 alg flgs iter salt hash <$> genNsecTypes
    genTextString = do
        len <- elements [0, 1, 63, 255, 256, 511, 512, 1023, 1024]
        B.pack <$> replicateM len genWord8
    genNsecTypes = do
        ntypes <- elements [0..15]
        types <- sequence $ replicate ntypes $ toTYPE <$> elements [1..1024]
        return $ [ the t |
                   t <- types,
                   then group by (fromTYPE t)
                        using groupWith ]

genIPv4 :: Gen IPv4
genIPv4 = toIPv4 <$> replicateM 4 (fromIntegral <$> genWord8)

genIPv6 :: Gen IPv6
genIPv6 = toIPv6 <$> replicateM 8 (fromIntegral <$> genWord16)

genByteString :: Gen BS.ByteString
genByteString = elements
    [ "", "a", "a.b", "abc", "a.b.c", "a\\.b.c", "\\001.a.b", "\\$.a.b" ]

genMboxString :: Gen BS.ByteString
genMboxString = elements
    [ "", "a", "a@b", "abc", "a@b.c", "first.last@example.org" ]

genDomain :: Gen Domain
genDomain = do
    bs <- genByteString
    pure $ bs <> "."

genMailbox :: Gen Mailbox
genMailbox = do
    bs <- genMboxString
    pure $ bs <> "."

genDNSHeader :: Word16 -> Gen DNSHeader
genDNSHeader maxrc = DNSHeader <$> genWord16 <*> genDNSFlags maxrc

genDNSFlags :: Word16 -> Gen DNSFlags
genDNSFlags maxrc =
  DNSFlags <$> genQorR <*> genOPCODE <*> genBool        <*> genBool
           <*> genBool <*> genBool   <*> genRCODE maxrc <*> genBool <*> genBool

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

genRCODE :: Word16 -> Gen RCODE
genRCODE maxrc = elements $ map toRCODE [0..maxrc]

genEDNS :: Gen EDNS
genEDNS = do
    vers <- genWord8
    ok <- genBool
    od <- genOData
    us <- elements [minUdpSize..maxUdpSize]
    return $ defaultEDNS {
        ednsVersion  = vers
      , ednsUdpSize  = us
      , ednsDnssecOk = ok
      , ednsOptions  = [od]
      }

genOData :: Gen OData
genOData = oneof
    [ genOD_Unknown
    , genOD_ECS
    ]
  where
    -- | Choose from the range reserved for local use
    -- https://tools.ietf.org/html/rfc6891#section-9
    genOD_Unknown = UnknownOData <$> elements [65001, 65534] <*> genByteString

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
            else if srcBits < bits1
                 then pure $ OD_ECSgeneric fam srcBits scpBits $ B.pack more
                 else pure $ OD_ECSgeneric fam srcBits scpBits $ B.pack less

genExtRCODE :: Gen RCODE
genExtRCODE = elements $ map toRCODE [0..4095]

genEDNSHeader :: Gen (EDNS, DNSHeader)
genEDNSHeader = do
    edns <- genEDNS
    hdr <- genDNSHeader 0xF00
    return (edns, hdr)
