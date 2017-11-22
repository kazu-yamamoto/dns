-- | Miscellaneous utility functions for processing DNS data.
--
module Network.DNS.Utils (
    normalize
  , normalizeCase
  , normalizeRoot
  ) where

import qualified Data.ByteString.Char8 as BS (
    append
  , last
  , map
  , null
  , pack )
import Data.Char (toLower)

import Network.DNS.Types (Domain)


-- | Perform both 'normalizeCase' and 'normalizeRoot' on the given
--   'Domain'. When comparing DNS names taken from user input, this is
--   often necessary to avoid unexpected results.
--
--   /Examples/:
--
--   >>> let domain1 = BS.pack "ExAmPlE.COM"
--   >>> let domain2 = BS.pack "example.com."
--   >>> domain1 == domain2
--   False
--   >>> normalize domain1 == normalize domain2
--   True
--
--   The 'normalize' function should be idempotent:
--
--   >>> normalize (normalize domain1) == normalize domain1
--   True
--
--   Ensure that we don't crash on the empty 'Domain':
--
--   >>> import qualified Data.ByteString.Char8 as BS ( empty )
--   >>> normalize BS.empty
--   "."
--
normalize :: Domain -> Domain
normalize = normalizeCase . normalizeRoot


-- | Normalize the case of the given DNS name for comparisons.
--
--   According to RFC #1035, \"For all parts of the DNS that are part
--   of the official protocol, all comparisons between character
--   strings (e.g., labels, domain names, etc.) are done in a
--   case-insensitive manner.\" This function chooses to lowercase
--   its argument, but that should be treated as an implementation
--   detail if at all possible.
--
--   /Examples/:
--
--   >>> let domain1 = BS.pack "ExAmPlE.COM"
--   >>> let domain2 = BS.pack "exAMPle.com"
--   >>> domain1 == domain2
--   False
--   >>> normalizeCase domain1 == normalizeCase domain2
--   True
--
--   The 'normalizeCase' function should be idempotent:
--
--   >>> normalizeCase (normalizeCase domain2) == normalizeCase domain2
--   True
--
--   Ensure that we don't crash on the empty 'Domain':
--
--   >>> import qualified Data.ByteString.Char8 as BS ( empty )
--   >>> normalizeCase BS.empty
--   ""
--
normalizeCase :: Domain -> Domain
normalizeCase = BS.map toLower


-- | Normalize the given name by appending a trailing dot (the DNS
--   root) if one does not already exist.
--
--   Warning: this does not produce an equivalent DNS name! However,
--   users are often unaware of the effect that the absence of the
--   root will have. In user interface design, it may therefore be
--   wise to act as if the user supplied the trailing dot during
--   comparisons.
--
--   Per RFC #1034,
--
--   \"Since a complete domain name ends with the root label, this leads
--   to a printed form which ends in a dot. We use this property to
--   distinguish between:
--
--   * a character string which represents a complete domain name
--     (often called \'absolute\'). For example, \'poneria.ISI.EDU.\'
--
--   * a character string that represents the starting labels of a
--     domain name which is incomplete, and should be completed by
--     local software using knowledge of the local domain (often
--     called \'relative\'). For example, \'poneria\' used in the
--     ISI.EDU domain.
--
--   Relative names are either taken relative to a well known origin,
--   or to a list of domains used as a search list. Relative names
--   appear mostly at the user interface, where their interpretation
--   varies from implementation to implementation, and in master
--   files, where they are relative to a single origin domain name.\"
--
--   /Examples/:
--
--   >>> let domain1 = BS.pack "example.com"
--   >>> let domain2 = BS.pack "example.com."
--   >>> domain1 == domain2
--   False
--   >>> normalizeRoot domain1 == normalizeRoot domain2
--   True
--
--   The 'normalizeRoot' function should be idempotent:
--
--   >>> normalizeRoot (normalizeRoot domain1) == normalizeRoot domain1
--   True
--
--   Ensure that we don't crash on the empty 'Domain':
--
--   >>> import qualified Data.ByteString.Char8 as BS ( empty )
--   >>> normalizeRoot BS.empty
--   "."
--
normalizeRoot :: Domain -> Domain
normalizeRoot d
  | BS.null d = trailing_dot
  | BS.last d == '.' = d
  | otherwise = d `BS.append` trailing_dot
    where
      trailing_dot = BS.pack "."
