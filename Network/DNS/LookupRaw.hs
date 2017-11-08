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

import Data.ByteString.Short (toShort)
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

-- | Looking up resource records of a domain. The first parameter is one of
--   the field accessors of the 'DNSMessage' type -- this allows you to
--   choose which section (answer, authority, or additional) you would like
--   to inspect for the result.

lookupSection :: (DNSMessage -> [ResourceRecord])
              -> Resolver
              -> Domain
              -> TYPE
              -> IO (Either DNSError [RData])
lookupSection section rlv dom typ = case mcacheConf of
    Nothing -> do
        eans <- lookupRaw rlv dom typ
        case eans of
          Left err  -> return $ Left err
          Right ans -> return $ fromDNSMessage ans toRData
    Just cacheconf -> lookupCacheSection section rlv dom typ cacheconf
  where
    correct ResourceRecord{..} = rrtype == typ
    toRData = map rdata . filter correct . section
    mcacheConf = resolvCache $ resolvconf $ resolvseed rlv

lookupCacheSection :: (DNSMessage -> [ResourceRecord])
                   -> Resolver
                   -> Domain
                   -> TYPE
                   -> CacheConf
                   -> IO (Either DNSError [RData])
lookupCacheSection section rlv dom typ cconf = do
    mx <- lookupCacheRef (sdom,typ) cref
    case mx of
      Nothing -> do
          eans <- lookupRaw rlv dom typ
          case eans of
            Left  err -> do
                let v = Left err
                insertNegative cconf cref key v
                return v
            Right ans -> do
                let errs = fromDNSMessage ans toRR
                case errs of
                  Left  err -> do
                      let v = Left err
                      insertNegative cconf cref key v
                      return v
                  Right rss -> do
                      let rds = map rdata rss
                          v = Right rds
                          ttls = map rrttl rss
                      insertPositive cconf cref key v ttls
                      return v
      Just (_,x) -> return x
  where
    correct ResourceRecord{..} = rrtype == typ
    toRR = filter correct . section
    cref = cache rlv
    sdom = toShort dom
    key = (sdom,typ)

insertPositive :: CacheConf -> CacheRef -> Key -> Entry -> [TTL] -> IO ()
insertPositive CacheConf{..} ref k v ttls = do
    tim <- addUTCTime life <$> getCurrentTime
    insertCacheRef k tim v ref
  where
    life = fromIntegral $ case ttls of
      []    -> minimumTTL -- fixme: what is a proper value?
      ttl:_ -> minimumTTL `max` (maximumTTL `min` ttl)

insertNegative :: CacheConf -> CacheRef -> Key -> Entry -> IO ()
insertNegative CacheConf{..} ref k v = do
    let life = fromIntegral negativeTTL
    tim <- addUTCTime life <$> getCurrentTime
    insertCacheRef k tim v ref

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
lookup = lookupSection answer

-- | Look up resource records of a specified type for a domain,
--   collecting the results
--   from the AUTHORITY section of the response.
--   See manual the manual of 'lookupRaw'
--   to understand the concrete behavior.
lookupAuth :: Resolver -> Domain -> TYPE -> IO (Either DNSError [RData])
lookupAuth = lookupSection authority

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
