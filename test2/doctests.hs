{-# LANGUAGE CPP #-}
module Main where

-- | Run doctests only on non-Windows systems.
--
-- The Windows doctests now compile and run, but either succeed quickly or
-- randomly hang (before AppVeyor kills them after an hour).  So we disable
-- these for now.  This can be tested again at some point in the future.
--
#if !defined(mingw32_HOST_OS)

import Build_doctests (flags, pkgs, module_sources)
import Test.DocTest (doctest)

main :: IO ()
main = do
    putStrLn $ unwords $ "\ndoctest args: " : args
    doctest args
  where
    args = [ "-XCPP" ] ++
           flags ++
           pkgs ++ ["-package=dns"] ++
           module_sources
#else

main :: IO ()
main = return ()

#endif
