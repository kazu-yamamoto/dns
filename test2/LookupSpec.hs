{-# LANGUAGE OverloadedStrings #-}

module LookupSpec where

import Control.Applicative
import qualified Data.ByteString.Char8 as BS
import Data.List
import Network.DNS as DNS
import Test.Hspec

spec :: Spec
spec = do
    describe "lookupA" $ do
        it "gets IPv4 addresses" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver ->
                DNS.lookupA resolver "www.mew.org"
                    `shouldReturn`
                    Right ["202.232.15.101"]

        it "gets IPv4 addresses via CNAME" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver ->
                DNS.lookupA resolver "www.kame.net"
                    `shouldReturn`
                    Right ["203.178.141.194"]

        it "returns TimeoutExpired on timeout" $ do
            -- Use a timeout of one millisecond.
            let badrc = defaultResolvConf { resolvTimeout = 1 }
            rs <- makeResolvSeed badrc
            withResolver rs $ \resolver ->
                DNS.lookupA resolver "www.example.com"
                    `shouldReturn`
                    Left TimeoutExpired

    describe "lookupAAAA" $ do
        it "gets IPv6 addresses" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver -> do
                DNS.lookupAAAA resolver "mew.org"
                    `shouldReturn`
                    Right []

                DNS.lookupAAAA resolver "www.mew.org"
                    `shouldReturn`
                    Right ["2001:240:11e:c00::101"]

    describe "lookupNS" $ do
        it "gets NS" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver -> do
                actual <- DNS.lookupNS resolver "mew.org"
                let expected = Right ["ns1.mew.org.", "ns2.mew.org."]
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

    describe "lookupAviaMX" $ do
        it "gets IPv4 addresses via MX" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver -> do
                as <- DNS.lookupAviaMX resolver "mixi.jp"
                sort <$> as `shouldBe` Right ["202.32.29.4", "202.32.29.5"]

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
