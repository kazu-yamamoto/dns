{-# LANGUAGE OverloadedStrings #-}

module TestProtocol where

import Network.DNS
import Network.DNS.Internal
import Network.DNS.Query
import Network.DNS.Response
import Data.IP
import Test.Framework (defaultMain, testGroup, Test)
import Test.Framework.Providers.HUnit
import Test.HUnit hiding (Test)

tests :: [Test]
tests = 
  [ testGroup "Test case"
      [ testCase "QueryA" (test_Format testQueryA)
      , testCase "QueryAAAA" (test_Format testQueryAAAA)
      , testCase "ResponseA" (test_Format testResponseA)
      ]
  ]

defaultHeader :: DNSHeader
defaultHeader = header defaultQuery

testQueryA :: DNSFormat
testQueryA = defaultQuery
  { header = defaultHeader
      { identifier = 1000
      , qdCount = 1
      }
  , question = [makeQuestion "www.mew.org." A]
  }

testQueryAAAA :: DNSFormat
testQueryAAAA = defaultQuery
  { header = defaultHeader
      { identifier = 1000
      , qdCount = 1
      }
  , question = [makeQuestion "www.mew.org." AAAA]
  }

testResponseA :: DNSFormat
testResponseA = DNSFormat { header = DNSHeader { identifier = 61046
                               , flags = DNSFlags { qOrR = QR_Response
                                                  , opcode = OP_STD
                                                  , authAnswer = False
                                                  , trunCation = False
                                                  , recDesired = True
                                                  , recAvailable = True
                                                  , rcode = NoErr
                                                  }
                               , qdCount = 1
                               , anCount = 8
                               , nsCount = 2
                               , arCount = 4
                               }
          , question = [Question {qname = "492056364.qzone.qq.com.", qtype = A}]
          , answer = [ ResourceRecord { rrname = "492056364.qzone.qq.com."
                                      , rrtype = A
                                      , rrttl = 568
                                      , rdlen = 4
                                      , rdata = RD_A $ toIPv4 [119, 147, 15, 122]
                                      }
                     , ResourceRecord { rrname = "492056364.qzone.qq.com."
                                      , rrtype = A
                                      , rrttl = 568
                                      , rdlen = 4
                                      , rdata = RD_A $ toIPv4 [119, 147, 79, 106]
                                      }
                     , ResourceRecord { rrname = "492056364.qzone.qq.com."
                                      , rrtype = A
                                      , rrttl = 568
                                      , rdlen = 4
                                      , rdata = RD_A $ toIPv4 [183, 60, 55, 43]
                                      }
                     , ResourceRecord { rrname = "492056364.qzone.qq.com."
                                      , rrtype = A
                                      , rrttl = 568
                                      , rdlen = 4
                                      , rdata = RD_A $ toIPv4 [183, 60, 55, 107]
                                      }
                     , ResourceRecord { rrname = "492056364.qzone.qq.com."
                                      , rrtype = A
                                      , rrttl = 568
                                      , rdlen = 4
                                      , rdata = RD_A $ toIPv4 [113, 108, 7, 172]
                                      }
                     , ResourceRecord { rrname = "492056364.qzone.qq.com."
                                      , rrtype = A
                                      , rrttl = 568
                                      , rdlen = 4
                                      , rdata = RD_A $ toIPv4 [113, 108, 7, 174]
                                      }
                     , ResourceRecord { rrname = "492056364.qzone.qq.com."
                                      , rrtype = A
                                      , rrttl = 568
                                      , rdlen = 4
                                      , rdata = RD_A $ toIPv4 [113, 108, 7, 175]
                                      }
                     , ResourceRecord { rrname = "492056364.qzone.qq.com."
                                      , rrtype = A
                                      , rrttl = 568
                                      , rdlen = 4
                                      , rdata = RD_A $ toIPv4 [119, 147, 15, 100]
                                      }
                     ]
          , authority = [ ResourceRecord { rrname = "qzone.qq.com."
                                         , rrtype = NS
                                         , rrttl = 45919
                                         , rdlen = 10
                                         , rdata = RD_NS "ns-tel2.qq.com."
                                         }
                        , ResourceRecord { rrname = "qzone.qq.com."
                                         , rrtype = NS
                                         , rrttl = 45919
                                         , rdlen = 10
                                         , rdata = RD_NS "ns-tel1.qq.com."
                                         }
                        ]
          , additional = [ ResourceRecord { rrname = "ns-tel1.qq.com."
                                          , rrtype = A
                                          , rrttl = 46520
                                          , rdlen = 4
                                          , rdata = RD_A $ toIPv4 [121, 14, 73, 115]
                                          }
                         , ResourceRecord { rrname = "ns-tel2.qq.com."
                                          , rrtype = A
                                          , rrttl = 2890
                                          , rdlen = 4
                                          , rdata = RD_A $ toIPv4 [222, 73, 76, 226]
                                          }
                         , ResourceRecord { rrname = "ns-tel2.qq.com."
                                          , rrtype = A
                                          , rrttl = 2890
                                          , rdlen = 4
                                          , rdata = RD_A $ toIPv4 [183, 60, 3, 202]
                                          }
                         , ResourceRecord { rrname = "ns-tel2.qq.com."
                                          , rrtype = A
                                          , rrttl = 2890
                                          , rdlen = 4
                                          , rdata = RD_A $ toIPv4 [218, 30, 72, 180]
                                          }
                         ]
          }

assertEither :: (a -> String) -> Either a b -> IO ()
assertEither f = either (assertFailure . f) (const $ return ())

test_Format :: DNSFormat -> IO ()
test_Format fmt = do
    assertEither id result
    let (Right fmt') = result
    assertEqual "fail" fmt fmt'
  where
    bs = composeDNSFormat fmt 
    result = runDNSFormat_ bs

main :: IO ()
main = defaultMain tests
