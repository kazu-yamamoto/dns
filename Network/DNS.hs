{-|
  Thread-safe DNS library written in Haskell.

  This code is written in Haskell, not using FFI.

  Sample code for DNS lookup:

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
  -- * High level
    module Network.DNS.Lookup
  , module Network.DNS.Resolver
  , module Network.DNS.Types
  -- * Low level
  , module Network.DNS.Decode
  , module Network.DNS.Encode
  ) where

import Network.DNS.Lookup
import Network.DNS.Resolver
import Network.DNS.Types
import Network.DNS.Decode
import Network.DNS.Encode


