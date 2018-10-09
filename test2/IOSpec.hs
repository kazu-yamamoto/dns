{-# LANGUAGE OverloadedStrings #-}

module IOSpec where

import Data.Monoid ((<>))
import Network.DNS.IO as DNS
import Network.DNS.Types as DNS
import Network.Socket hiding (send)
import Test.Hspec

spec :: Spec
spec = describe "send/receive" $ do

    it "resolves well with UDP" $ do
        let hints = defaultHints { addrFamily = AF_INET, addrSocketType = Datagram, addrFlags = [AI_NUMERICHOST]}
        addr:_ <- getAddrInfo (Just hints) (Just "8.8.8.8") (Just "domain")
        sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
        connect sock $ addrAddress addr
        -- Google's resolvers support the AD and CD bits
        let qry = encodeQuestions 1 [Question "www.mew.org" A] [] $
                  rdBit FlagSet <> adBit FlagSet <> cdBit FlagSet
        send sock qry
        ans <- receive sock
        identifier (header ans) `shouldBe` 1

    it "resolves well with TCP" $ do
        let hints = defaultHints { addrFamily = AF_INET, addrSocketType = Stream, addrFlags = [AI_NUMERICHOST]}
        addr:_ <- getAddrInfo (Just hints) (Just "8.8.8.8") (Just "domain")
        sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
        connect sock $ addrAddress addr
        let qry = encodeQuestions 1 [Question "www.mew.org" A] [] $
                  rdBit FlagSet <> adBit FlagClear <> cdBit FlagSet
        sendVC sock qry
        ans <- receiveVC sock
        identifier (header ans) `shouldBe` 1
