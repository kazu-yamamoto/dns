{-# LANGUAGE CPP #-}

module Main where

import Test.DocTest

main :: IO ()
main = doctest [
    "-XOverloadedStrings"
  , "-XCPP"
  {-
    Both 'iproute' and 'network-data' provide
    ‘Data.IP’ package:
      Ambiguous interface for ‘Data.IP’:
        it was found in multiple packages: network-data-0.5.3 iproute-1.7.0
    We ignore network-data to make tests pass.
  -}
  , "-package=array"
  , "-package=async"
  , "-package=attoparsec"
  , "-package=auto-update"
  , "-package=base16-bytestring"
  , "-package=base64-bytestring"
  , "-package=bytestring"
  , "-package=containers"
  , "-package=cryptonite"
  , "-package=hourglass"
  , "-package=iproute"
  , "-package=mtl"
  , "-package=network"
  , "-package=psqueues"
  , "Network/DNS.hs"
  , "Network/DNS/Decode/Parsers.hs"
  , "Network/DNS/Lookup.hs"
  , "Network/DNS/LookupRaw.hs"
  , "Network/DNS/Resolver.hs"
  , "Network/DNS/Types.hs"
  , "Network/DNS/Types/Internal.hs"
  , "Network/DNS/Utils.hs"
  ]
