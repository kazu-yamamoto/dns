{-# LANGUAGE OverloadedStrings, TemplateHaskell #-}

module Test where

import qualified Data.ByteString.Char8 as BS
import Data.List
import Network.DNS as DNS
import Test.Framework.Providers.HUnit
import Test.Framework.TH
import Test.HUnit

----------------------------------------------------------------

main :: IO ()
main = $(defaultMainGenerator)

----------------------------------------------------------------

(?=) :: (Eq a, Show a) => IO a -> a -> IO ()
a ?= b = a >>= (@?= b)

case_lookupA :: Assertion
case_lookupA = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        DNS.lookupA resolver "www.mew.org" ?= Just ["202.232.15.101"]

(??=) :: (Ord a, Show a) => IO (Maybe [a]) -> [a] -> Assertion
a ??= bs = do
    mas <- a
    case mas of
        Nothing -> False @? "should be Nothing"
        Just as -> sort as @?= sort bs

case_lookupAAAA :: Assertion
case_lookupAAAA = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver -> do
        DNS.lookupAAAA resolver "mew.org" ?= Nothing
        DNS.lookupAAAA resolver "www.mew.org" ?= Just ["2001:240:11e:c00::101"]

case_lookupTXT :: Assertion
case_lookupTXT = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        DNS.lookupTXT resolver "mew.org" ?= Just ["v=spf1 +mx -all"]

case_lookupAviaMX :: Assertion
case_lookupAviaMX = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        DNS.lookupAviaMX resolver "mixi.jp" ??= ["202.32.29.4", "202.32.29.5"]

case_lookupAviaCNAME :: Assertion
case_lookupAviaCNAME = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        DNS.lookupA resolver "ghs.google.com" ??= ["72.14.203.121"]

case_lookupPTR :: Assertion
case_lookupPTR = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        DNS.lookupPTR resolver rev ?= Just ["www-v4.iij.ad.jp."]
  where
    target = "210.130.137.80"
    rev = BS.intercalate "." (reverse (BS.split '.' target))
          `BS.append` ".in-addr.arpa"

case_lookupSRV :: Assertion
case_lookupSRV = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        DNS.lookupSRV resolver "_sip._tcp.cisco.com" ?= Just [(1,0,5060,"vcsgw.cisco.com.")]
