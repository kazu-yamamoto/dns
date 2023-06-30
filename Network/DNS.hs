-- | A thread-safe DNS library for both clients and servers written
--   in pure Haskell.
--   The Network.DNS module re-exports all other exposed modules for
--   convenience.
--   Applications will most likely use the high-level interface, while
--   library/daemon authors may need to use the lower-level one.
--   EDNS and TCP fallback are supported.
--
--   Examples:
--
--   >>> :set -XOverloadedStrings
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupA resolver "192.0.2.1.nip.io"
--   Right [192.0.2.1]
module Network.DNS (
  -- * High level
    module Network.DNS.Lookup
  -- | This module contains simple functions to
  --   perform various DNS lookups. If you simply want to resolve a
  --   hostname ('lookupA'), or find a domain's MX record
  --   ('lookupMX'), this is the easiest way to do it.

  , module Network.DNS.Resolver
  -- | Resolver related data types.

  , module Network.DNS.Types
  -- | All of the types that the other modules use.

  , module Network.DNS.Utils
  -- | This module contains utility functions used
  --   for processing DNS data.

  -- * Middle level
  , module Network.DNS.LookupRaw
  -- | This provides the 'lookup', 'lookupAuth', 'lookupRaw' and
  --   'lookupRawCtl' functions for any resource records.

  -- * Low level
  , module Network.DNS.Encode
  -- | Encoding a query or response.

  , module Network.DNS.Decode
  -- | Decoding a qurey or response.

  , module Network.DNS.IO
  -- | Sending and receiving.
) where

import Network.DNS.Decode
import Network.DNS.Encode
import Network.DNS.IO
import Network.DNS.Lookup
import Network.DNS.LookupRaw
import Network.DNS.Resolver
import Network.DNS.Types
import Network.DNS.Utils
