module Network.DNS.Types.Internal where

import Data.List.NonEmpty (NonEmpty(..))
import Network.Socket (AddrInfo(..), PortNumber(..), HostName)
import Data.Word (Word16)

import Network.DNS.Types

----------------------------------------------------------------

-- | The type to specify a cache server.
data FileOrNumericHost = RCFilePath FilePath -- ^ A path for \"resolv.conf\"
                                             -- where one or more IP addresses
                                             -- of DNS servers should be found
                                             -- on Unix.
                                             -- Default DNS servers are
                                             -- automatically detected
                                             -- on Windows regardless of
                                             -- the value of the file name.
                       | RCHostName HostName -- ^ A numeric IP address. /Warning/: host names are invalid.
                       | RCHostNames [HostName] -- ^ Numeric IP addresses. /Warning/: host names are invalid.
                       | RCHostPort HostName PortNumber -- ^ A numeric IP address and port number. /Warning/: host names are invalid.
                       deriving Show

-- | Type for resolver configuration.
--  Use 'defaultResolvConf' to create a new value.
--
--  An example to use Google's public DNS cache instead of resolv.conf:
--
--  >>> let conf = defaultResolvConf { resolvInfo = RCHostName "8.8.8.8" }
--
--  An example to disable EDNS0:
--
--  >>> let conf = defaultResolvConf { resolvEDNS = [] }
--
--  An example to disable EDNS0 with a 1,280-bytes buffer:
--
--  >>> let conf = defaultResolvConf { resolvEDNS = [fromEDNS0 defaultEDNS0 { udpSize = 1280 }] }
data ResolvConf = ResolvConf {
   -- | Server information.
    resolvInfo    :: FileOrNumericHost
   -- | Timeout in micro seconds.
  , resolvTimeout :: Int
   -- | The number of retries including the first try.
  , resolvRetry   :: Int
   -- | Additional resource records to specify EDNS.
  , resolvEDNS    :: [ResourceRecord]
} deriving Show

-- | Return a default 'ResolvConf':
--
--     * 'resolvInfo' is 'RCFilePath' \"\/etc\/resolv.conf\".
--
--     * 'resolvTimeout' is 3,000,000 micro seconds.
--
--     * 'resolvRetry' is 3.
--
--     * 'resolvEDNS' is EDNS0 with a 4,096-bytes buffer.
defaultResolvConf :: ResolvConf
defaultResolvConf = ResolvConf {
    resolvInfo    = RCFilePath "/etc/resolv.conf"
  , resolvTimeout = 3 * 1000 * 1000
  , resolvRetry   = 3
  , resolvEDNS    = [fromEDNS0 defaultEDNS0]
}

----------------------------------------------------------------

-- | Abstract data type of DNS Resolver seed.
--   IP address information of DNS servers is generated
--   according to 'resolvInfo' internally.
--   This value can be safely reused for 'withResolver'.
--
--   The naming is confusing for historical reasons.
data ResolvSeed = ResolvSeed {
    resolvconf  :: ResolvConf
  , nameservers :: NonEmpty AddrInfo
}

----------------------------------------------------------------

-- | Abstract data type of DNS Resolver.
--   This includes a newly seeded random generator for DNS packet identifiers.
data Resolver = Resolver {
    resolvseed :: ResolvSeed
  , genId      :: IO Word16
}