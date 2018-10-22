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
        sock <- connectedSocket Datagram
        -- Google's resolvers support the AD and CD bits
        let qry = encodeQuestion 1 (Question "www.mew.org" A) $
                  adFlag FlagSet <> ednsEnabled FlagClear
        send sock qry
        ans <- receive sock
        identifier (header ans) `shouldBe` 1

    it "resolves well with TCP" $ do
        sock <- connectedSocket Stream
        let qry = encodeQuestion 1 (Question "www.mew.org" A) $
                  adFlag FlagClear <> cdFlag FlagSet <> doFlag FlagSet
        sendVC sock qry
        ans <- receiveVC sock
        identifier (header ans) `shouldBe` 1

connectedSocket :: SocketType -> IO Socket
connectedSocket typ = do
    let hints = defaultHints { addrFamily = AF_INET, addrSocketType = typ, addrFlags = [AI_NUMERICHOST]}
    addr:_ <- getAddrInfo (Just hints) (Just "8.8.8.8") (Just "domain")
    sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
    connect sock $ addrAddress addr
    return sock
