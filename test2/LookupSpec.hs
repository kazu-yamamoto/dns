{-# LANGUAGE OverloadedStrings #-}

module LookupSpec where

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

