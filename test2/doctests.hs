module Main where

import Build_doctests (flags, pkgs, module_sources)
import Test.DocTest (doctest)

main :: IO ()
main = do
    putStrLn $ unwords $ "\ndoctest args: " : args
    doctest args
  where
    args = [ "-XCPP" ] ++
           flags ++
           pkgs ++
           module_sources
