{-# LANGUAGE OverloadedStrings #-}

module EncodeSpec where

import Data.IP
import Network.DNS
import Network.DNS.Internal (defaultQuery, makeQuestion)
import Test.Hspec

spec :: Spec
spec = do
    describe "encode" $ do
        it "encodes DNSMessage correctly" $ do
            check1 testQueryA
            check1 testQueryAAAA
            check1 testResponseA
            check1 testResponseTXT

    describe "decode" $ do
        it "decodes DNSMessage correctly" $ do
            check2 testQueryA
            check2 testQueryAAAA
            check2 testResponseA
            check2 testResponseTXT

check1 :: DNSMessage -> Expectation
check1 inp = out `shouldBe` Right inp
  where
    bs = encode inp
    out = decode bs

check2 :: DNSMessage -> Expectation
check2 inp = bs' `shouldBe` bs
  where
    bs = encode inp
    Right out = decode bs
    bs' = encode out

defaultHeader :: DNSHeader
defaultHeader = header defaultQuery

testQueryA :: DNSMessage
testQueryA = defaultQuery {
    header = defaultHeader {
         identifier = 1000
       }
  , question = [makeQuestion "www.mew.org." A]
  }

testQueryAAAA :: DNSMessage
testQueryAAAA = defaultQuery {
    header = defaultHeader {
         identifier = 1001
       }
  , question = [makeQuestion "www.mew.org." AAAA]
  }

testResponseA :: DNSMessage
testResponseA = DNSMessage {
    header = DNSHeader {
         identifier = 61046
       , flags = DNSFlags {
           qOrR = QR_Response
         , opcode = OP_STD
         , authAnswer = False
         , trunCation = False
         , recDesired = True
         , recAvailable = True
         , rcode = NoErr
         , authenData = False
         }
       }
  , question = [Question {
                     qname = "492056364.qzone.qq.com."
                   , qtype = A
                   }
                ]
  , answer =
        [ ResourceRecord "492056364.qzone.qq.com." A 568 (RD_A $ toIPv4 [119, 147, 15, 122])
        , ResourceRecord "492056364.qzone.qq.com." A 568 (RD_A $ toIPv4 [119, 147, 79, 106])
        , ResourceRecord "492056364.qzone.qq.com." A 568 (RD_A $ toIPv4 [183, 60, 55, 43])
        , ResourceRecord "492056364.qzone.qq.com." A 568 (RD_A $ toIPv4 [183, 60, 55, 107])
        , ResourceRecord "492056364.qzone.qq.com." A 568 (RD_A $ toIPv4 [113, 108, 7, 172])
        , ResourceRecord "492056364.qzone.qq.com." A 568 (RD_A $ toIPv4 [113, 108, 7, 174])
        , ResourceRecord "492056364.qzone.qq.com." A 568 (RD_A $ toIPv4 [113, 108, 7, 175])
        , ResourceRecord "492056364.qzone.qq.com." A 568 (RD_A $ toIPv4 [119, 147, 15, 100])
        ]
  , authority =
        [ ResourceRecord "qzone.qq.com." NS 45919 (RD_NS "ns-tel2.qq.com.")
        , ResourceRecord "qzone.qq.com." NS 45919 (RD_NS "ns-tel1.qq.com.")
        ]
  , additional =
        [ ResourceRecord "ns-tel1.qq.com." A 46520 (RD_A $ toIPv4 [121, 14, 73, 115])
        , ResourceRecord "ns-tel2.qq.com." A 2890 (RD_A $ toIPv4 [222, 73, 76, 226])
        , ResourceRecord "ns-tel2.qq.com." A 2890 (RD_A $ toIPv4 [183, 60, 3, 202])
        , ResourceRecord "ns-tel2.qq.com." A 2890 (RD_A $ toIPv4 [218, 30, 72, 180])
        ]
  }

testResponseTXT :: DNSMessage
testResponseTXT = DNSMessage {
    header = DNSHeader {
         identifier = 48724
       , flags = DNSFlags {
           qOrR = QR_Response
         , opcode = OP_STD
         , authAnswer = False
         , trunCation = False
         , recDesired = True
         , recAvailable = True
         , rcode = NoErr
         , authenData = False
         }
       }
  , question = [Question {
                     qname = "492056364.qzone.qq.com."
                   , qtype = TXT
                   }
                ]
  , answer =
        [ ResourceRecord "492056364.qzone.qq.com." TXT 0 (RD_TXT "simple txt line")
        ]
  , authority =
        [ ResourceRecord "qzone.qq.com." NS 45919 (RD_NS "ns-tel2.qq.com.")
        , ResourceRecord "qzone.qq.com." NS 45919 (RD_NS "ns-tel1.qq.com.")
        ]
  , additional =
        [ ResourceRecord "ns-tel1.qq.com." A 46520 (RD_A $ toIPv4 [121, 14, 73, 115])
        , ResourceRecord "ns-tel2.qq.com." A 2890 (RD_A $ toIPv4 [222, 73, 76, 226])
        , ResourceRecord "ns-tel2.qq.com." A 2890 (RD_A $ toIPv4 [183, 60, 3, 202])
        , ResourceRecord "ns-tel2.qq.com." A 2890 (RD_A $ toIPv4 [218, 30, 72, 180])
        ]
  }
