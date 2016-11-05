-- | Simple, high-level DNS lookup functions.
--
--   All of the lookup functions necessary run in IO, since they
--   interact with the network. The return types are similar, but
--   differ in what can be returned from a successful lookup.
--
--   We can think of the return type as \"either what I asked for, or
--   an error\". For example, the 'lookupA' function, if successful,
--   will return a list of 'IPv4'. The 'lookupMX' function will
--   instead return a list of @('Domain',Int)@ pairs, where each pair
--   represents a hostname and its associated priority.
--
--   The order of multiple results may not be consistent between
--   lookups. If you require consistent results, apply
--   'Data.List.sort' to the returned list.
--
--   The errors that can occur are the same for all lookups. Namely:
--
--     * Timeout
--
--     * Wrong sequence number (foul play?)
--
--     * Unexpected data in the response
--
--   If an error occurs, you should be able to pattern match on the
--   'DNSError' constructor to determine which of these is the case.
--
--   /Note/: A result of \"no records\" is not considered an
--   error. If you perform, say, an \'AAAA\' lookup for a domain with
--   no such records, the \"success\" result would be @Right []@.
--
--   We perform a successful lookup of \"www.example.com\":
--
--   >>> let hostname = Data.ByteString.Char8.pack "www.example.com"
--   >>>
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupA resolver hostname
--   Right [93.184.216.34]
--
--   The only error that we can easily cause is a timeout. We do this
--   by creating and utilizing a 'ResolvConf' which has a timeout of
--   one millisecond:
--
--   >>> let hostname = Data.ByteString.Char8.pack "www.example.com"
--   >>> let badrc = defaultResolvConf { resolvTimeout = 1 }
--   >>>
--   >>> rs <- makeResolvSeed badrc
--   >>> withResolver rs $ \resolver -> lookupA resolver hostname
--   Left TimeoutExpired
--
--   As is the convention, successful results will always be wrapped
--   in a 'Right', while errors will be wrapped in a 'Left'.
--
--   For convenience, you may wish to enable GHC's OverloadedStrings
--   extension. This will allow you to avoid calling
--   'Data.ByteString.Char8.pack' on each domain name. See
--   <http://www.haskell.org/ghc/docs/7.6.3/html/users_guide/type-class-extensions.html#overloaded-strings>
--   for more information.
--
module Network.DNS.Lookup (
    lookupA, lookupAAAA
  , lookupMX, lookupAviaMX, lookupAAAAviaMX
  , lookupNS
  , lookupNSAuth
  , lookupTXT
  , lookupPTR
  , lookupRDNS
  , lookupSRV
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.IP (IPv4, IPv6)
import Network.DNS.Resolver as DNS
import Network.DNS.Types

----------------------------------------------------------------

-- | Look up all \'A\' records for the given hostname.
--
--   A straightforward example:
--
--   >>> let hostname = Data.ByteString.Char8.pack "www.mew.org"
--   >>>
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupA resolver hostname
--   Right [210.130.207.72]
--
--   This function will also follow a CNAME and resolve its target if
--   one exists for the queries hostname:
--
--   >>> let hostname = Data.ByteString.Char8.pack "www.kame.net"
--   >>>
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupA resolver hostname
--   Right [203.178.141.194]
--
lookupA :: Resolver -> Domain -> IO (Either DNSError [IPv4])
lookupA rlv dom = do
  erds <- DNS.lookup rlv dom A
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RData -> Either DNSError IPv4
    unTag (RD_A x) = Right x
    unTag _ = Left UnexpectedRDATA


-- | Look up all (IPv6) \'AAAA\' records for the given hostname.
--
--   Examples:
--
--   >>> let hostname = Data.ByteString.Char8.pack "www.wide.ad.jp"
--   >>>
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupAAAA resolver hostname
--   Right [2001:200:dff:fff1:216:3eff:fe4b:651c]
--
lookupAAAA :: Resolver -> Domain -> IO (Either DNSError [IPv6])
lookupAAAA rlv dom = do
  erds <- DNS.lookup rlv dom AAAA
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RData -> Either DNSError IPv6
    unTag (RD_AAAA x) = Right x
    unTag _ = Left UnexpectedRDATA

----------------------------------------------------------------

-- | Look up all \'MX\' records for the given hostname. Two parts
--   constitute an MX record: a hostname , and an integer priority. We
--   therefore return each record as a @('Domain', Int)@.
--
--   In this first example, we look up the MX for the domain
--   \"example.com\". It has no MX (to prevent a deluge of spam from
--   examples posted on the internet). But remember, \"no results\" is
--   still a successful result.
--
--   >>> let hostname = Data.ByteString.Char8.pack "example.com"
--   >>>
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupMX resolver hostname
--   Right []
--
--   The domain \"mew.org\" does however have a single MX:
--
--   >>> let hostname = Data.ByteString.Char8.pack "mew.org"
--   >>>
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupMX resolver hostname
--   Right [("mail.mew.org.",10)]
--
--   Also note that all hostnames are returned with a trailing dot to
--   indicate the DNS root.
--
lookupMX :: Resolver -> Domain -> IO (Either DNSError [(Domain,Int)])
lookupMX rlv dom = do
  erds <- DNS.lookup rlv dom MX
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RData -> Either DNSError (Domain,Int)
    unTag (RD_MX pr dm) = Right (dm,pr)
    unTag _ = Left UnexpectedRDATA

-- | Look up all \'MX\' records for the given hostname, and then
--   resolve their hostnames to IPv4 addresses by calling
--   'lookupA'. The priorities are not retained.
--
--   Examples:
--
--   >>> import Data.List (sort)
--   >>> let hostname = Data.ByteString.Char8.pack "wide.ad.jp"
--   >>>
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> ips <- withResolver rs $ \resolver -> lookupAviaMX resolver hostname
--   >>> fmap sort ips
--   Right [133.138.10.34,203.178.136.49]
--
--   Since there is more than one result, it is necessary to sort the
--   list in order to check for equality.
--
lookupAviaMX :: Resolver -> Domain -> IO (Either DNSError [IPv4])
lookupAviaMX rlv dom = lookupXviaMX rlv dom (lookupA rlv)

-- | Look up all \'MX\' records for the given hostname, and then
--   resolve their hostnames to IPv6 addresses by calling
--   'lookupAAAA'. The priorities are not retained.
--
lookupAAAAviaMX :: Resolver -> Domain -> IO (Either DNSError [IPv6])
lookupAAAAviaMX rlv dom = lookupXviaMX rlv dom (lookupAAAA rlv)

lookupXviaMX :: Resolver
             -> Domain
             -> (Domain -> IO (Either DNSError [a]))
             -> IO (Either DNSError [a])
lookupXviaMX rlv dom func = do
    edps <- lookupMX rlv dom
    case edps of
      -- We have to deconstruct and reconstruct the error so that the
      -- typechecker does not conclude that a ~ (Domain, Int).
      Left err -> return (Left err)
      Right dps -> do
        -- We'll get back a [Either DNSError a] here.
        responses <- mapM (func . fst) dps
        -- We can use 'sequence' to join all of the Eithers
        -- together. If any of them are (Left _), we'll get a Left
        -- overall. Otherwise, we'll get Right [a].
        let overall = sequence responses
        -- Finally, we use (fmap concat) to concatenate the responses
        -- if there were no errors.
        return $ fmap concat overall



----------------------------------------------------------------

-- | This function performs the real work for both 'lookupNS' and
--   'lookupNSAuth'. The only difference between those two is which
--   function, 'lookup' or 'lookupAuth', is used to perform the
--   lookup. We take either of those as our first parameter.
lookupNSImpl :: (Resolver -> Domain -> TYPE -> IO (Either DNSError [RData]))
             -> Resolver
             -> Domain
             -> IO (Either DNSError [Domain])
lookupNSImpl lookup_function rlv dom = do
  erds <- lookup_function rlv dom NS
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RData -> Either DNSError Domain
    unTag (RD_NS dm) = Right dm
    unTag _ = Left UnexpectedRDATA

-- | Look up all \'NS\' records for the given hostname. The results
--   are taken from the ANSWER section of the response (as opposed to
--   AUTHORITY). For details, see e.g.
--   <http://www.zytrax.com/books/dns/ch15/>.
--
--   There will typically be more than one name server for a
--   domain. It is therefore extra important to sort the results if
--   you prefer them to be at all deterministic.
--
--   Examples:
--
--   >>> import Data.List (sort)
--   >>> let hostname = Data.ByteString.Char8.pack "mew.org"
--   >>>
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> ns <- withResolver rs $ \resolver -> lookupNS resolver hostname
--   >>> fmap sort ns
--   Right ["ns1.mew.org.","ns2.mew.org."]
--
lookupNS :: Resolver -> Domain -> IO (Either DNSError [Domain])
lookupNS = lookupNSImpl DNS.lookup

-- | Look up all \'NS\' records for the given hostname. The results
--   are taken from the AUTHORITY section of the response and not the
--   usual ANSWER (use 'lookupNS' for that). For details, see e.g.
--   <http://www.zytrax.com/books/dns/ch15/>.
--
--   There will typically be more than one name server for a
--   domain. It is therefore extra important to sort the results if
--   you prefer them to be at all deterministic.
--
--   For an example, we can look up the nameservers for
--   \"example.com\" from one of the root servers, a.gtld-servers.net,
--   the IP address of which was found beforehand:
--
--   >>> import Data.List (sort)
--   >>> let hostname = Data.ByteString.Char8.pack "example.com"
--   >>>
--   >>> let ri = RCHostName "192.5.6.30" -- a.gtld-servers.net
--   >>> let rc = defaultResolvConf { resolvInfo = ri }
--   >>> rs <- makeResolvSeed rc
--   >>> ns <- withResolver rs $ \resolver -> lookupNSAuth resolver hostname
--   >>> fmap sort ns
--   Right ["a.iana-servers.net.","b.iana-servers.net."]
--
lookupNSAuth :: Resolver -> Domain -> IO (Either DNSError [Domain])
lookupNSAuth = lookupNSImpl DNS.lookupAuth


----------------------------------------------------------------

-- | Look up all \'TXT\' records for the given hostname. The results
--   are free-form 'ByteString's.
--
--   Two common uses for \'TXT\' records are
--   <http://en.wikipedia.org/wiki/Sender_Policy_Framework> and
--   <http://en.wikipedia.org/wiki/DomainKeys_Identified_Mail>. As an
--   example, we find the SPF record for \"mew.org\":
--
--   >>> let hostname = Data.ByteString.Char8.pack "mew.org"
--   >>>
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupTXT resolver hostname
--   Right ["v=spf1 +mx -all"]
--
lookupTXT :: Resolver -> Domain -> IO (Either DNSError [ByteString])
lookupTXT rlv dom = do
  erds <- DNS.lookup rlv dom TXT
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RData -> Either DNSError ByteString
    unTag (RD_TXT x) = Right x
    unTag _ = Left UnexpectedRDATA

----------------------------------------------------------------

-- | Look up all \'PTR\' records for the given hostname. To perform a
--   reverse lookup on an IP address, you must first reverse its
--   octets and then append the suffix \".in-addr.arpa.\"
--
--   We look up the PTR associated with the IP address
--   210.130.137.80, i.e., 80.137.130.210.in-addr.arpa:
--
--   >>> let hostname = Data.ByteString.Char8.pack "164.2.232.202.in-addr.arpa"
--   >>>
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupPTR resolver hostname
--   Right ["www.iij.ad.jp."]
--
--   The 'lookupRDNS' function is more suited to this particular task.
--
lookupPTR :: Resolver -> Domain -> IO (Either DNSError [Domain])
lookupPTR rlv dom = do
  erds <- DNS.lookup rlv dom PTR
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RData -> Either DNSError Domain
    unTag (RD_PTR dm) = Right dm
    unTag _ = Left UnexpectedRDATA


-- | Convenient wrapper around 'lookupPTR' to perform a reverse lookup
--   on a single IP address.
--
--   We repeat the example from 'lookupPTR', except now we pass the IP
--   address directly:
--
--   >>> let hostname = Data.ByteString.Char8.pack "202.232.2.164"
--   >>>
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupRDNS resolver hostname
--   Right ["www.iij.ad.jp."]
--
lookupRDNS :: Resolver -> Domain -> IO (Either DNSError [Domain])
lookupRDNS rlv ip = lookupPTR rlv dom
  where
    -- ByteString constants.
    dot = BS.pack "."
    suffix = BS.pack ".in-addr.arpa"

    octets = BS.split '.' ip
    reverse_ip = BS.intercalate dot (reverse octets)
    dom = reverse_ip `BS.append` suffix

----------------------------------------------------------------

-- | Look up all \'SRV\' records for the given hostname. SRV records
--   consist (see <https://tools.ietf.org/html/rfc2782>) of the
--   following four fields:
--
--     * Priority (lower is more-preferred)
--
--     * Weight (relative frequency with which to use this record
--       amongst all results with the same priority)
--
--     * Port (the port on which the service is offered)
--
--     * Target (the hostname on which the service is offered)
--
--   The first three are integral, and the target is another DNS
--   hostname. We therefore return a four-tuple
--   @(Int,Int,Int,'Domain')@.
--
--   Examples:
--
--   >>> let q = Data.ByteString.Char8.pack "_xmpp-server._tcp.jabber.ietf.org"
--   >>>
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupSRV resolver q
--   Right [(5,0,5269,"jabber.ietf.org.")]

-- Though the "jabber.ietf.orgs" SRV record may prove reasonably stable, as
-- with anything else published in DNS it is subject to change.  Also, this
-- example only works when connected to the Internet.  Perhaps the above
-- example should be displayed in a format that is not recognized as a test
-- by "doctest".

lookupSRV :: Resolver -> Domain -> IO (Either DNSError [(Int,Int,Int,Domain)])
lookupSRV rlv dom = do
  erds <- DNS.lookup rlv dom SRV
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RData -> Either DNSError (Int,Int,Int,Domain)
    unTag (RD_SRV pri wei prt dm) = Right (pri,wei,prt,dm)
    unTag _ = Left UnexpectedRDATA
