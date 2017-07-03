{-# LANGUAGE OverloadedStrings, CPP #-}

module RoundTripSpec where

import Control.Monad (replicateM)
import Data.IP (IP (..), IPv4, IPv6, toIPv4, toIPv6)
import qualified Data.ByteString.Char8 as BS
import Network.DNS.Internal
import Network.DNS.Decode
import Network.DNS.Encode
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck (Gen, arbitrary, choose, elements, forAll, frequency, listOf, oneof)
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
        intToType (typeToInt t) `shouldBe` t

    prop "Domain" . forAll genDomain $ \ dom -> do
        let bs = encodeDomain dom
        decodeDomain bs `shouldBe` Right dom
        fmap encodeDomain (decodeDomain bs) `shouldBe` Right bs

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
    , (1, intToType <$> genWord16)
    ]

genResourceRecord :: Gen ResourceRecord
genResourceRecord = frequency
    [ (8, genRR)
    -- fixme: Add this back in when it works.
    , (0, genOptRecord)
    ]
  where
    genRR = do
      dom <- genDomain
      t <- elements [A , AAAA, NS, TXT, MX, CNAME, SOA, PTR, SRV, DNAME, DS]
      ResourceRecord dom t <$> genWord32 <*> mkRData dom t
    genRDataOpt = do
      odata <- listOf genOData
      pure $ ResourceRecord "" OPT (fromIntegral $ length odata) (RD_OPT odata)
    genOptRecord = do
      dom <- genDomain
      t <- genTYPE
      OptRecord <$> genWord16 <*> genBool <*> genWord8 <*> mkRData dom t

mkRData :: Domain -> TYPE -> Gen RData
mkRData dom typ =
    case typ of
        A -> RD_A <$> genIPv4
        AAAA -> RD_AAAA <$> genIPv6
        NS -> pure $ RD_NS dom
        TXT -> RD_TXT <$> genByteString
        MX -> RD_MX <$> genWord16 <*> genDomain
        CNAME -> pure $ RD_CNAME dom
        SOA -> RD_SOA dom <$> genDomain <*> genWord32 <*> genWord32 <*> genWord32 <*> genWord32 <*> genWord32
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

genOData :: Gen OData
genOData = oneof
    [ genOD_Unknown
    , OD_ClientSubnet <$> genWord8 <*> genWord8 <*> oneof [ IPv4 <$> genIPv4, IPv6 <$> genIPv6 ]
    ]
  where
    genOD_Unknown = do
      bs <- genByteString
      pure $ OD_Unknown (fromIntegral $ BS.length bs) bs

genByteString :: Gen BS.ByteString
genByteString = elements
    [ "", "a", "a.b", "abc", "a.b.c" ]

genDomain :: Gen Domain
genDomain = do
    bs <- genByteString
    pure $ bs <> "."

genDNSHeader :: Gen DNSHeader
genDNSHeader = DNSHeader <$> genWord16 <*> genDNSFlags

genDNSFlags :: Gen DNSFlags
genDNSFlags =
  DNSFlags <$> genQorR <*> genOPCODE <*> genBool <*> genBool
            <*> genBool <*> genBool <*> genRCODE <*> genBool

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
genOPCODE  = elements [minBound .. maxBound]

genRCODE :: Gen RCODE
genRCODE = elements [minBound .. maxBound]
