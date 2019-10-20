{-# LANGUAGE CPP #-}

module Main where

import Test.DocTest
import System.Environment

-- | List of modules to run through doctests
modules :: [String]
modules =
  [ "-XOverloadedStrings"
  , "-XCPP"
  , "-i", "-i.", "-iInternal"
  , "Network/DNS.hs"
  ]

-- | Run doctests only non-windows systems with GHC 8.4 or later
main :: IO ()
main = do
#if !defined(mingw32_HOST_OS) && MIN_TOOL_VERSION_ghc(8,4,0)
    getArgs >>= doctest . (++ modules)
#endif
    return ()
