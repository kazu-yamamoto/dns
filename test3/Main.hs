{-# LANGUAGE OverloadedStrings #-}

import Conduit
import Network.DNS
import Network.DNS.ZoneTransfer.Conduit

main :: IO ()
main = do
  rs <- makeResolvSeed defaultResolvConf { resolvInfo = RCHostName "81.4.108.41" }
  withResolver rs $ \resolver -> (runConduitRes $ zoneTransferC resolver "zonetransfer.me" .| sinkList) >>= print . length
