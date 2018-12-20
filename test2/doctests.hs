module Main where

import Build_doctests (flags, pkgs, module_sources)
import Data.Foldable (traverse_)
import Test.DocTest (doctest)
import System.IO (hFlush, hPutStrLn, stderr)

main :: IO ()
main = do
    traverse_ (hPutStrLn stderr) args
    hFlush stderr
    doctest args
  where
    args = [ "-XOverloadedStrings"
           , "-XCPP"
           , "--verbose" ] ++
           flags ++
           pkgs ++
           module_sources
