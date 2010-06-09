{-# LANGUAGE OverloadedStrings #-}

module Test where

import Data.IP
import Data.List
import Network.DNS as DNS
import Test.Framework (defaultMain, testGroup, Test)
import Test.Framework.Providers.HUnit
import Test.HUnit hiding (Test)

tests :: [Test]
tests = [
    testGroup "Test case" [
         testCase "lookupA" test_lookupA
       , testCase "lookupAAAA" test_lookupAAAA
       , testCase "lookupTXT" test_lookupTXT
       , testCase "lookupAviaMX" test_lookupAviaMX
       , testCase "lookupAviaCNAME" test_lookupAviaCNAME
       ]
  ]

(?=) :: (Eq a, Show a) => IO a -> a -> IO ()
a ?= b = a >>= (@?= b)

test_lookupA :: IO ()
test_lookupA = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        DNS.lookupA resolver "www.mew.org" ?= Just [toIPv4 [202,232,15,101]]

(??=) :: (Ord a, Show a) => IO (Maybe [a]) -> [a] -> IO ()
a ??= bs = do
    mas <- a
    case mas of
        Nothing -> False @? "should be Nothing"
        Just as -> sort as @?= sort bs

test_lookupAAAA :: IO ()
test_lookupAAAA = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver -> do
        DNS.lookupAAAA resolver "mew.org" ?= Nothing
        DNS.lookupAAAA resolver "www.mew.org" ?= Just [read "2001:240:11e:c00::101"]

test_lookupTXT :: IO ()
test_lookupTXT = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        DNS.lookupTXT resolver "mew.org" ?= Just ["v=spf1 +mx -all"]

test_lookupAviaMX :: IO ()
test_lookupAviaMX = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        DNS.lookupAviaMX resolver "mixi.jp" ??= [read "202.32.29.4", read "202.32.29.5"]

test_lookupAviaCNAME :: IO ()
test_lookupAviaCNAME = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        DNS.lookupA resolver "foundry1.hongo.wide.ad.jp" ??= [read "203.178.135.1", read "203.178.138.230"]

main :: IO ()
main = defaultMain tests
