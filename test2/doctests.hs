{-# LANGUAGE CPP #-}

-- | Run doctests only on non-Windows systems with GHC 8.4 or later.
--
-- The Windows doctests now compile and run, but either succeed quickly or
-- randomly hang (before AppVeyor kills them after an hour).  So we disable
-- these for now.  This can be tested again at some point in the future.
--
module Main where

#if !defined(mingw32_HOST_OS) && MIN_TOOL_VERSION_ghc(8,4,0)
import Data.Version
import Paths_dns
import Test.DocTest
import System.Environment

libraryPackageId, internalLibrary :: String
libraryPackageId = "dns-" ++ showVersion version ++ "-inplace"
internalLibrary = "dns-internal"

-- | Expose precompiled library modules.
modules :: [String]
modules =
  [ "-XOverloadedStrings"
  , "-XCPP"
  , "-threaded"
  , "-i", "-i."
  , "-package-id=" ++ libraryPackageId
  , "-package-id=" ++ libraryPackageId ++ "-" ++ internalLibrary
  , "Network/DNS.hs"
  ]

main :: IO ()
main = getArgs >>= doctest . (++ modules)

#else

main :: IO ()
main = return ()

#endif
