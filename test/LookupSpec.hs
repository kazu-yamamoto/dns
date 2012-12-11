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
                DNS.lookupA resolver "www.mew.org" `shouldReturn` Just ["202.232.15.101"]

        it "gets IPv4 addresses via CNAME" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver ->
                DNS.lookupA resolver "www.kame.net" `shouldReturn` Just ["203.178.141.194"]

    describe "lookupAAAA" $ do
        it "gets IPv6 addresses" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver -> do
                DNS.lookupAAAA resolver "mew.org" `shouldReturn` Nothing
                DNS.lookupAAAA resolver "www.mew.org" `shouldReturn` Just ["2001:240:11e:c00::101"]

    describe "lookupTXT" $ do
        it "gets TXT" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver ->
                DNS.lookupTXT resolver "mew.org" `shouldReturn` Just ["v=spf1 +mx -all"]

    describe "lookupAviaMX" $ do
        it "gets IPv4 addresses via MX" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver -> do
                as <- DNS.lookupAviaMX resolver "mixi.jp"
                sort <$> as `shouldBe` Just ["202.32.29.4", "202.32.29.5"]

    describe "lookupPTR" $ do
        it "gets PTR" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver -> do
                let target = "210.130.137.80"
                    rev = BS.intercalate "." (reverse (BS.split '.' target))
                            `BS.append` ".in-addr.arpa"
                DNS.lookupPTR resolver rev `shouldReturn` Just ["www-v4.iij.ad.jp."]

    describe "lookupSRV" $ do
        it "gets SRV" $ do
            rs <- makeResolvSeed defaultResolvConf
            withResolver rs $ \resolver ->
                DNS.lookupSRV resolver "_sip._tcp.cisco.com" `shouldReturn` Just [(1,0,5060,"vcsgw.cisco.com.")]
