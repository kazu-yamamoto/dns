module Main where

import Test.DocTest

main :: IO ()
main = doctest [
    "-XOverloadedStrings"
  {-
    Both 'iproute' and 'network-data' provide
    ‘Data.IP’ package:
      Ambiguous interface for ‘Data.IP’:
        it was found in multiple packages: network-data-0.5.3 iproute-1.7.0
    We ignore network-data to make tests pass.
  -}
  , "-ignore-package=network-data"
  , "Network/DNS.hs"
  ]
