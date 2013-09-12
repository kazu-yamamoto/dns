{-# LANGUAGE OverloadedStrings #-}

module LookupSpec where

import Control.Applicative
import qualified Data.ByteString.Char8 as BS
import Data.List
import Network.DNS as DNS
import Test.Hspec

spec :: Spec
spec = do

    describe "lookupAAAA" $ do
        it "gets IPv6 addresses" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver -> do
                DNS.lookupAAAA resolver "mew.org"
                    `shouldReturn`
                    Right []

    describe "lookupNSAuth" $ do
        it "gets NS" $ do
            -- We expect the GTLD servers to return the NS in the
            -- AUTHORITY section of the response.
            let ri = RCHostName "192.5.6.30" -- a.gtld-servers.net
            let rc = defaultResolvConf { resolvInfo = ri }
            rs <- makeResolvSeed rc
            withResolver rs $ \resolver -> do
                actual <- DNS.lookupNSAuth resolver "example.com"
                let expected = Right ["a.iana-servers.net.",
                                      "b.iana-servers.net."]
                -- The order of NS records is variable, so we sort the
                -- result.
                sort <$> actual `shouldBe` expected

    describe "lookupTXT" $ do
        it "gets TXT" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver ->
                DNS.lookupTXT resolver "mew.org"
                    `shouldReturn`
                    Right ["v=spf1 +mx -all"]

    describe "lookupPTR" $ do
        it "gets PTR" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver -> do
                let target = "210.130.137.80"
                    rev = BS.intercalate "." (reverse (BS.split '.' target))
                            `BS.append` ".in-addr.arpa"
                DNS.lookupPTR resolver rev
                    `shouldReturn`
                    Right ["www-v4.iij.ad.jp."]

    describe "lookupSRV" $ do
        it "gets SRV" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver ->
                DNS.lookupSRV resolver "_sip._tcp.cisco.com"
                    `shouldReturn`
                    Right [(1,0,5060,"vcsgw.cisco.com.")]
