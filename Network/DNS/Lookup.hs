-- | Simple, high-level DNS lookup functions for clients.
--
--   All of the lookup functions necessary run in IO since they
--   interact with the network. The return types are similar, but
--   differ in what can be returned from a successful lookup.
--
--   We can think of the return type as either \"what I asked for\" or
--   \"an error\". For example, the 'lookupA' function, if successful,
--   will return a list of 'IPv4'. The 'lookupMX' function will
--   instead return a list of @('Domain','Int')@ pairs, where each pair
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
--   one millisecond and a very limited number of retries:
--
--   >>> let hostname = Data.ByteString.Char8.pack "www.example.com"
--   >>> let badrc = defaultResolvConf { resolvTimeout = 0, resolvRetry = 1 }
--   >>>
--   >>> rs <- makeResolvSeed badrc
--   >>> withResolver rs $ \resolver -> lookupA resolver hostname
--   Left RetryLimitExceeded
--
--   As is the convention, successful results will always be wrapped
--   in a 'Right' while errors will be wrapped in a 'Left'.
--
--   For convenience, you may wish to enable GHC\'s OverloadedStrings
--   extension. This will allow you to avoid calling
--   'Data.ByteString.Char8.pack' on each domain name. See
--   <https://downloads.haskell.org/~ghc/latest/docs/html/users_guide/glasgow_exts.html#overloaded-string-literals>
--   for more information. In the following examples,
--   we assuem this extension is enabled.
--
--   All lookup functions eventually call 'lookupRaw'. See its documentation
--   to understand the concrete lookup behavior.
module Network.DNS.Lookup (
    lookupA, lookupAAAA
  , lookupMX, lookupAviaMX, lookupAAAAviaMX
  , lookupNS
  , lookupNSAuth
  , lookupTXT
  , lookupSOA
  , lookupPTR
  , lookupRDNS
  , lookupSRV
  , lookupAXFR
  ) where

import qualified Data.ByteString.Char8 as BS
import Data.IP (IPv4, IPv6)

import Network.DNS.Imports
import Network.DNS.LookupRaw as DNS
import Network.DNS.Resolver as DNS
import Network.DNS.Types

-- $setup
-- >>> :set -XOverloadedStrings

----------------------------------------------------------------

-- | Look up all \'A\' records for the given hostname.
--
--   A straightforward example:
--
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupA resolver "www.mew.org"
--   Right [210.130.207.72]
--
--   This function will also follow a CNAME and resolve its target if
--   one exists for the queries hostname:
--
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupA resolver "www.kame.net"
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
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupAAAA resolver "www.wide.ad.jp"
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
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupMX resolver "example.com"
--   Right []
--
--   The domain \"mew.org\" does however have a single MX:
--
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupMX resolver "mew.org"
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
    unTag (RD_MX pr dm) = Right (dm, fromIntegral pr)
    unTag _ = Left UnexpectedRDATA

-- | Look up all \'MX\' records for the given hostname, and then
--   resolve their hostnames to IPv4 addresses by calling
--   'lookupA'. The priorities are not retained.
--
--   Examples:
--
--   >>> import Data.List (sort)
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> ips <- withResolver rs $ \resolver -> lookupAviaMX resolver "wide.ad.jp"
--   >>> fmap sort ips
--   Right [133.138.10.39,203.178.136.30]
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
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> ns <- withResolver rs $ \resolver -> lookupNS resolver "mew.org"
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
--   >>> let ri = RCHostName "192.5.6.30" -- a.gtld-servers.net
--   >>> let rc = defaultResolvConf { resolvInfo = ri }
--   >>> rs <- makeResolvSeed rc
--   >>> ns <- withResolver rs $ \resolver -> lookupNSAuth resolver "example.com"
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
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupTXT resolver "mew.org"
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

-- | Look up the \'SOA\' record for the given domain. The result 7-tuple
--   consists of the \'mname\', \'rname\', \'serial\', \'refresh\', \'retry\',
--   \'expire\' and \'minimum\' fields of the SOA record.
--
--   An \@ separator is used between the first and second labels of the
--   \'rname\' field.  Since \'rname\' is an email address, it often contains
--   periods within its first label.  Presently, the trailing period is not
--   removed from the domain part of the \'rname\', but this may change in the
--   future.  Users should be prepared to remove any trailing period before
--   using the \'rname\` as a contact email address.
--
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupSOA resolver "mew.org"
--   Right [("ns1.mew.org.","kazu@mew.org.",201406240,3600,300,3600000,3600)]
--
lookupSOA :: Resolver -> Domain -> IO (Either DNSError [(Domain,Mailbox,Word32,Word32,Word32,Word32,Word32)])
lookupSOA rlv dom = do
  erds <- DNS.lookup rlv dom SOA
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RData -> Either DNSError (Domain,Mailbox,Word32,Word32,Word32,Word32,Word32)
    unTag (RD_SOA mn mr serial refresh retry expire mini) = Right (mn, mr, serial, refresh, retry, expire, mini)
    unTag _ = Left UnexpectedRDATA

----------------------------------------------------------------

-- | Look up all \'PTR\' records for the given hostname. To perform a
--   reverse lookup on an IP address, you must first reverse its
--   octets and then append the suffix \".in-addr.arpa.\"
--
--   We look up the PTR associated with the IP address
--   210.130.137.80, i.e., 80.137.130.210.in-addr.arpa:
--
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupPTR resolver "164.2.232.202.in-addr.arpa"
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
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupRDNS resolver "202.232.2.164"
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
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookupSRV resolver "_xmpp-server._tcp.jabber.ietf.org"
--   Right [(5,0,5269,"jabber.ietf.org.")]

-- Though the "jabber.ietf.orgs" SRV record may prove reasonably stable, as
-- with anything else published in DNS it is subject to change.  Also, this
-- example only works when connected to the Internet.  Perhaps the above
-- example should be displayed in a format that is not recognized as a test
-- by "doctest".

lookupSRV :: Resolver -> Domain -> IO (Either DNSError [(Word16, Word16, Word16, Domain)])
lookupSRV rlv dom = do
  erds <- DNS.lookup rlv dom SRV
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RData -> Either DNSError (Word16, Word16, Word16, Domain)
    unTag (RD_SRV pri wei prt dm) = Right (pri,wei,prt,dm)
    unTag _ = Left UnexpectedRDATA

----------------------------------------------------------------

-- | Look up all records in the given zone (see
-- <https://tools.ietf.org/html/rfc5936>).
--
-- Note that most DNS servers are configured to only respond to zone transfer
-- coming from "known" DNS servers (see
-- https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/, from which
-- the example below was crafted)
--
--   Examples:
--
--   >>> rs <- makeResolvSeed defaultResolvConf { resolvInfo = RCHostName "81.4.108.41" }
--   >>> withResolver rs $ \resolver -> lookupAXFR resolver "zonetransfer.me"
--   Right [ResourceRecord {rrname = "zonetransfer.me.", rrtype = SOA, rrclass = 1, rrttl = 7200, rdata = nsztm1.digi.ninja. robin@digi.ninja. 2017042001 172800 900 1209600 3600},ResourceRecord {rrname = "zonetransfer.me.", rrtype = TYPE13, rrclass = 1, rrttl = 300, rdata = \# 25 0d436173696f2066782d373030470a57696e646f7773205850},ResourceRecord {rrname = "zonetransfer.me.", rrtype = TXT, rrclass = 1, rrttl = 301, rdata = google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA},ResourceRecord {rrname = "zonetransfer.me.", rrtype = MX, rrclass = 1, rrttl = 7200, rdata = 0 ASPMX.L.GOOGLE.COM.},ResourceRecord {rrname = "zonetransfer.me.", rrtype = MX, rrclass = 1, rrttl = 7200, rdata = 10 ALT1.ASPMX.L.GOOGLE.COM.},ResourceRecord {rrname = "zonetransfer.me.", rrtype = MX, rrclass = 1, rrttl = 7200, rdata = 10 ALT2.ASPMX.L.GOOGLE.COM.},ResourceRecord {rrname = "zonetransfer.me.", rrtype = MX, rrclass = 1, rrttl = 7200, rdata = 20 ASPMX2.GOOGLEMAIL.COM.},ResourceRecord {rrname = "zonetransfer.me.", rrtype = MX, rrclass = 1, rrttl = 7200, rdata = 20 ASPMX3.GOOGLEMAIL.COM.},ResourceRecord {rrname = "zonetransfer.me.", rrtype = MX, rrclass = 1, rrttl = 7200, rdata = 20 ASPMX4.GOOGLEMAIL.COM.},ResourceRecord {rrname = "zonetransfer.me.", rrtype = MX, rrclass = 1, rrttl = 7200, rdata = 20 ASPMX5.GOOGLEMAIL.COM.},ResourceRecord {rrname = "zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 7200, rdata = 5.196.105.14},ResourceRecord {rrname = "zonetransfer.me.", rrtype = NS, rrclass = 1, rrttl = 7200, rdata = nsztm1.digi.ninja.},ResourceRecord {rrname = "zonetransfer.me.", rrtype = NS, rrclass = 1, rrttl = 7200, rdata = nsztm2.digi.ninja.},ResourceRecord {rrname = "_sip._tcp.zonetransfer.me.", rrtype = SRV, rrclass = 1, rrttl = 14000, rdata = 0 0 5060www.zonetransfer.me.},ResourceRecord {rrname = "14.105.196.5.IN-ADDR.ARPA.zonetransfer.me.", rrtype = PTR, rrclass = 1, rrttl = 7200, rdata = www.zonetransfer.me.},ResourceRecord {rrname = "asfdbauthdns.zonetransfer.me.", rrtype = TYPE18, rrclass = 1, rrttl = 7900, rdata = \# 28 0001086173666462626f780c7a6f6e657472616e73666572026d6500},ResourceRecord {rrname = "asfdbbox.zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 7200, rdata = 127.0.0.1},ResourceRecord {rrname = "asfdbvolume.zonetransfer.me.", rrtype = TYPE18, rrclass = 1, rrttl = 7800, rdata = \# 28 0001086173666462626f780c7a6f6e657472616e73666572026d6500},ResourceRecord {rrname = "canberra-office.zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 7200, rdata = 202.14.81.230},ResourceRecord {rrname = "cmdexec.zonetransfer.me.", rrtype = TXT, rrclass = 1, rrttl = 300, rdata = ; ls},ResourceRecord {rrname = "contact.zonetransfer.me.", rrtype = TXT, rrclass = 1, rrttl = 2592000, rdata = Remember to call or email Pippa on +44 123 4567890 or pippa@zonetransfer.me when making DNS changes},ResourceRecord {rrname = "dc-office.zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 7200, rdata = 143.228.181.132},ResourceRecord {rrname = "deadbeef.zonetransfer.me.", rrtype = AAAA, rrclass = 1, rrttl = 7201, rdata = dead:beaf::},ResourceRecord {rrname = "dr.zonetransfer.me.", rrtype = TYPE29, rrclass = 1, rrttl = 300, rdata = \# 16 001216138b728cee7fa5c44a00989680},ResourceRecord {rrname = "DZC.zonetransfer.me.", rrtype = TXT, rrclass = 1, rrttl = 7200, rdata = AbCdEfG},ResourceRecord {rrname = "email.zonetransfer.me.", rrtype = TYPE35, rrclass = 1, rrttl = 2222, rdata = \# 56 000100010150094532552b656d61696c0005656d61696c0c7a6f6e657472616e73666572026d650c7a6f6e657472616e73666572026d6500},ResourceRecord {rrname = "email.zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 7200, rdata = 74.125.206.26},ResourceRecord {rrname = "home.zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 7200, rdata = 127.0.0.1},ResourceRecord {rrname = "Info.zonetransfer.me.", rrtype = TXT, rrclass = 1, rrttl = 7200, rdata = ZoneTransfer.me service provided by Robin Wood - robin@digi.ninja. See http://digi.ninja/projects/zonetransferme.php for more information.},ResourceRecord {rrname = "internal.zonetransfer.me.", rrtype = NS, rrclass = 1, rrttl = 300, rdata = intns1.zonetransfer.me.},ResourceRecord {rrname = "internal.zonetransfer.me.", rrtype = NS, rrclass = 1, rrttl = 300, rdata = intns2.zonetransfer.me.},ResourceRecord {rrname = "intns1.zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 300, rdata = 81.4.108.41},ResourceRecord {rrname = "intns2.zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 300, rdata = 167.88.42.94},ResourceRecord {rrname = "office.zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 7200, rdata = 4.23.39.254},ResourceRecord {rrname = "ipv6actnow.org.zonetransfer.me.", rrtype = AAAA, rrclass = 1, rrttl = 7200, rdata = 2001:67c:2e8:11::c100:1332},ResourceRecord {rrname = "owa.zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 7200, rdata = 207.46.197.32},ResourceRecord {rrname = "robinwood.zonetransfer.me.", rrtype = TXT, rrclass = 1, rrttl = 302, rdata = Robin Wood},ResourceRecord {rrname = "rp.zonetransfer.me.", rrtype = TYPE17, rrclass = 1, rrttl = 321, rdata = \# 50 05726f62696e0c7a6f6e657472616e73666572026d650009726f62696e776f6f640c7a6f6e657472616e73666572026d6500},ResourceRecord {rrname = "sip.zonetransfer.me.", rrtype = TYPE35, rrclass = 1, rrttl = 3333, rdata = \# 59 000200030150074532552b7369702b215e2e2a24217369703a637573746f6d65722d73657276696365407a6f6e657472616e736665722e6d652100},ResourceRecord {rrname = "sqli.zonetransfer.me.", rrtype = TXT, rrclass = 1, rrttl = 300, rdata = ' or 1=1 --},ResourceRecord {rrname = "sshock.zonetransfer.me.", rrtype = TXT, rrclass = 1, rrttl = 7200, rdata = () { :]}; echo ShellShocked},ResourceRecord {rrname = "staging.zonetransfer.me.", rrtype = CNAME, rrclass = 1, rrttl = 7200, rdata = www.sydneyoperahouse.com.},ResourceRecord {rrname = "alltcpportsopen.firewall.test.zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 301, rdata = 127.0.0.1},ResourceRecord {rrname = "testing.zonetransfer.me.", rrtype = CNAME, rrclass = 1, rrttl = 301, rdata = www.zonetransfer.me.},ResourceRecord {rrname = "vpn.zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 4000, rdata = 174.36.59.154},ResourceRecord {rrname = "www.zonetransfer.me.", rrtype = A, rrclass = 1, rrttl = 7200, rdata = 5.196.105.14},ResourceRecord {rrname = "xss.zonetransfer.me.", rrtype = TXT, rrclass = 1, rrttl = 300, rdata = '><script>alert('Boo')</script>}]

lookupAXFR :: Resolver -> Domain -> IO (Either DNSError [ResourceRecord])
lookupAXFR rlv dom = do
  erds <- DNS.lookupRaw rlv dom AXFR
  case erds of
    Left err  -> return (Left err)
    Right rds -> return . Right . answer $ rds
