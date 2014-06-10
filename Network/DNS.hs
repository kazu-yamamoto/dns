-- | A thread-safe DNS library for both clients and servers written
--   in pure Haskell.
--   The Network.DNS module re-exports all other exposed modules for
--   convenience.
--   Applications will most likely use the high-level interface, while
--   library/daemon authors may need to use the lower-level one.
--   EDNS0 and TCP fallback are not supported yet.
--
module Network.DNS (
  -- * High level
    module Network.DNS.Lookup
  -- | The "Network.DNS.Lookup" module contains simple functions to
  --   perform various DNS lookups. If you simply want to resolve a
  --   hostname ('lookupA'), or find a domain's MX record
  --   ('lookupMX'), this is the easiest way to do it.

  , module Network.DNS.Resolver
  -- | The "Network.DNS.Resolver" module is slightly more low-level
  --   than "Network.DNS.Lookup". If you need to do something unusual,
  --   you may need to use the 'lookup', 'lookupAuth', or 'lookupRaw'
  --   functions.

  , module Network.DNS.Utils
  -- | The "Network.DNS.Utils" module contains utility functions used
  --   for processing DNS data.

  , module Network.DNS.Types
  -- | All of the types that the other modules use.

  -- * Low level
  , module Network.DNS.Decode
  -- | Decoding a response.

  , module Network.DNS.Encode
  -- | Encoding a query.

  ) where

import Network.DNS.Lookup
import Network.DNS.Resolver
import Network.DNS.Utils
import Network.DNS.Types
import Network.DNS.Decode
import Network.DNS.Encode
