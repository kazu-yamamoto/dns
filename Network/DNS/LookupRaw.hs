{-# LANGUAGE RecordWildCards #-}

module Network.DNS.LookupRaw (
  -- * Looking up functions
    lookup
  , lookupAuth
  -- * Raw looking up function
  , lookupRaw
  , lookupRawAD
  , fromDNSMessage
  , fromDNSFormat
  ) where

import Control.Monad (when)
import Data.Time (getCurrentTime, addUTCTime)

import Network.DNS.IO
import Network.DNS.Memo
import Network.DNS.Transport
import Network.DNS.Types
import Network.DNS.Types.Internal

import Prelude hiding (lookup)

-- $setup
-- >>> import Network.DNS.Resolver

----------------------------------------------------------------

-- | Look up resource records of a specified type for a domain,
--   collecting the results
--   from the ANSWER section of the response.
--   See manual the manual of 'lookupRaw'
--   to understand the concrete behavior.
--   Cache is used if 'resolvCache' is 'Just'.
--
--   Example:
--
--   >>> rs <- makeResolvSeed defaultResolvConf
--   >>> withResolver rs $ \resolver -> lookup resolver "www.example.com" A
--   Right [93.184.216.34]
--
lookup :: Resolver -> Domain -> TYPE -> IO (Either DNSError [RData])
lookup = lookupSection Answer

-- | Look up resource records of a specified type for a domain,
--   collecting the results
--   from the AUTHORITY section of the response.
--   See manual the manual of 'lookupRaw'
--   to understand the concrete behavior.
--   Cache is used even if 'resolvCache' is 'Just'.
lookupAuth :: Resolver -> Domain -> TYPE -> IO (Either DNSError [RData])
lookupAuth = lookupSection Authority

----------------------------------------------------------------

-- | Looking up resource records of a domain. The first parameter is one of
--   the field accessors of the 'DNSMessage' type -- this allows you to
--   choose which section (answer, authority, or additional) you would like
--   to inspect for the result.

lookupSection :: Section
              -> Resolver
              -> Domain
              -> TYPE
              -> IO (Either DNSError [RData])
lookupSection section rlv dom typ
  | section == Authority = lookupFleshSection rlv dom typ section
  | otherwise = case mcacheConf of
      Nothing           -> lookupFleshSection rlv dom typ section
      Just cacheconf    -> lookupCacheSection rlv dom typ cacheconf
  where
    mcacheConf = resolvCache $ resolvconf $ resolvseed rlv

lookupFleshSection :: Resolver
                   -> Domain
                   -> TYPE
                   -> Section
                   -> IO (Either DNSError [RData])
lookupFleshSection rlv dom typ section = do
    eans <- lookupRaw rlv dom typ
    case eans of
      Left err  -> return $ Left err
      Right ans -> return $ fromDNSMessage ans toRData
  where
    correct ResourceRecord{..} = rrtype == typ
    toRData = map rdata . filter correct . sectionF
    sectionF = case section of
      Answer    -> answer
      Authority -> authority

lookupCacheSection :: Resolver
                   -> Domain
                   -> TYPE
                   -> CacheConf
                   -> IO (Either DNSError [RData])
lookupCacheSection rlv dom typ cconf = do
    mx <- lookupCache (dom,typ) c
    case mx of
      Nothing -> do
          eans <- lookupRaw rlv dom typ
          case eans of
            Left  err ->
                -- Probably a network error happens.
                -- We do not cache anything.
                return $ Left err
            Right ans -> do
                let ex = fromDNSMessage ans toRR
                case ex of
                  Left NameError -> do
                      let v = Left NameError
                      case filter (SOA `isTypeOf`) $ authority ans of
                        soa:_ -> insertNegative cconf c key v $ rrttl soa
                        _     -> return () -- does not cache anything
                      return v
                  Left e -> return $ Left e
                  Right rss0 -> do
                      let rds0 = map rdata rss0
                          rss = filter ((/= 0) . rrttl) rss0
                          rds = map rdata rss
                      case map rrttl rss of
                        []   -> return () -- does not cache anything
                        ttls -> let ttl = minimum ttls
                                in insertPositive cconf c key (Right rds) ttl
                      return $ Right rds0
      Just (_,x) -> return x
  where
    isTypeOf t ResourceRecord{..} = rrtype == t
    toRR = filter (typ `isTypeOf`) . answer
    Just c = cache rlv
    key = (dom,typ)

insertPositive :: CacheConf -> Cache -> Key -> Entry -> TTL -> IO ()
insertPositive CacheConf{..} c k v ttl = when (ttl /= 0) $ do
    tim <- addUTCTime life <$> getCurrentTime
    insertCache k tim v c
  where
    life = fromIntegral (minimumTTL `max` (maximumTTL `min` ttl))

insertNegative :: CacheConf -> Cache -> Key -> Entry -> TTL -> IO ()
insertNegative CacheConf{..} c k v ttl = when (ttl /= 0) $ do
    tim <- addUTCTime life <$> getCurrentTime
    insertCache k tim v c
  where
    life = fromIntegral ttl

----------------------------------------------------------------

-- | Look up a name and return the entire DNS Response
--
--  For a given DNS server, the queries are done:
--
--  * A new UDP socket bound to a new local port is created and
--    a new identifier is created atomically from the cryptographically
--    secure pseudo random number generator for the target DNS server.
--    Then UDP queries are tried with the limitation of 'resolvRetry'
--    (use EDNS0 if specifiecd).
--    If it appear that the target DNS server does not support EDNS0,
--    it falls back to traditional queries.
--
--  * If the response is truncated, a new TCP socket bound to a new
--    locla port is created. Then exactly one TCP query is retried.
--
--
-- If multiple DNS server are specified 'ResolvConf' ('RCHostNames ')
-- or found ('RCFilePath'), either sequential lookup or
-- concurrent lookup is carried out:
--
--  * In sequential lookup ('resolvConcurrent' is False),
--    the query procedure above is processed
--    in the order of the DNS servers sequentially until a successful
--    response is received.
--
--  * In concurrent lookup ('resolvConcurrent' is True),
--    the query procedure above is processed
--    for each DNS server concurrently.
--    The first received response is accepted even if
--    it is an error.
--
--  Cache is not used even if 'resolvCache' is 'Just'.
--
--   The example code:
--
--   @
--   rs <- makeResolvSeed defaultResolvConf
--   withResolver rs $ \\resolver -> lookupRaw resolver \"www.example.com\" A
--   @
--
--   And the (formatted) expected output:
--
--   @
--   Right (DNSMessage
--           { header = DNSHeader
--                        { identifier = 1,
--                          flags = DNSFlags
--                                    { qOrR = QR_Response,
--                                      opcode = OP_STD,
--                                      authAnswer = False,
--                                      trunCation = False,
--                                      recDesired = True,
--                                      recAvailable = True,
--                                      rcode = NoErr,
--                                      authenData = False
--                                    },
--                        },
--             question = [Question { qname = \"www.example.com.\",
--                                    qtype = A}],
--             answer = [ResourceRecord {rrname = \"www.example.com.\",
--                                       rrtype = A,
--                                       rrttl = 800,
--                                       rdlen = 4,
--                                       rdata = 93.184.216.119}],
--             authority = [],
--             additional = []})
--  @
--
lookupRaw :: Resolver -> Domain -> TYPE -> IO (Either DNSError DNSMessage)
lookupRaw rslv dom typ = resolve dom typ rslv False receive

-- | Same as 'lookupRaw' but the query sets the AD bit, which solicits the
--   the authentication status in the server reply.  In most applications
--   (other than diagnostic tools) that want authenticated data It is
--   unwise to trust the AD bit in the responses of non-local servers, this
--   interface should in most cases only be used with a loopback resolver.
--
lookupRawAD :: Resolver -> Domain -> TYPE -> IO (Either DNSError DNSMessage)
lookupRawAD rslv dom typ = resolve dom typ rslv True receive

----------------------------------------------------------------

-- | Extract necessary information from 'DNSMessage'
fromDNSMessage :: DNSMessage -> (DNSMessage -> a) -> Either DNSError a
fromDNSMessage ans conv = case errcode ans of
    NoErr     -> Right $ conv ans
    FormatErr -> Left FormatError
    ServFail  -> Left ServerFailure
    NameErr   -> Left NameError
    NotImpl   -> Left NotImplemented
    Refused   -> Left OperationRefused
    BadOpt    -> Left BadOptRecord
    _         -> Left UnknownDNSError
  where
    errcode = rcode . flags . header

{-# DEPRECATED fromDNSFormat "Use fromDNSMessage instead" #-}
-- | For backward compatibility.
fromDNSFormat :: DNSMessage -> (DNSMessage -> a) -> Either DNSError a
fromDNSFormat = fromDNSMessage
