module Main where

import Build_doctests (flags, pkgs, module_sources)
import Test.DocTest (doctest)
import System.Environment (getArgs)

main :: IO ()
main = do
    putStrLn $ unwords $ "\ndoctest args: " : args
    getArgs >>= doctest . (++) args
  where
    args = [ "-XCPP" ] ++
           flags ++
           pkgs ++
           module_sources
