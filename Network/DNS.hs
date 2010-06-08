{-|
  Thread-safe DNS library written in Haskell.

  Currently, only resolver side is supported. This code is written in
  Haskell, not using FFI. So, the \"-threaded\" option for GHC is not
  necessary.

  Sample code:

@
    import qualified Network.DNS as DNS (lookup)
    import Network.DNS hiding (lookup)
    main :: IO ()
    main = do
        rs <- makeResolvSeed defaultResolvConf
        withResolver rs $ \\resolver -> do
            DNS.lookup resolver \"www.example.com\" A >>= print
@
-}

module Network.DNS (
    module Network.DNS.Lookup
  , module Network.DNS.Resolver
  , module Network.DNS.Types
  ) where

import Network.DNS.Lookup
import Network.DNS.Resolver
import Network.DNS.Types
