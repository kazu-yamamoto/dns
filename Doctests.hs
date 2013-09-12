module Main
where

import Test.DocTest
import System.FilePath.Find ((==?), always, extension, find)

find_sources :: IO [FilePath]
find_sources = find always (extension ==? ".hs") "Network"

main :: IO ()
main = find_sources >>= doctest
