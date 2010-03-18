{-|
  DNS library written in Haskell.

  Currently, only resolver side is supported. This code is written in
  Haskell, not using FFI. So, the \"-threaded\" option for GHC is not
  necessary.

  Sample code:

@
    import qualified Network.DNS as DNS (lookup)
    import Network.DNS hiding (lookup)
    main :: IO ()
    main = makeDefaultResolver >>= DNS.lookup "www.iij.ad.jp" A >>= print
@
-}

module Network.DNS (
    module Network.DNS.Types
  , module Network.DNS.Resolver
  ) where

import Network.DNS.Types
import Network.DNS.Resolver
