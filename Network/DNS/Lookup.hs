{-|
  Upper level DNS lookup functions.
-}

module Network.DNS.Lookup (
    lookupA, lookupAAAA
  , lookupMX, lookupAviaMX, lookupAAAAviaMX
  , lookupNS
  , lookupTXT
  , lookupPTR
  , lookupSRV
  ) where

import Control.Applicative
import Data.ByteString (ByteString)
import Data.IP
import Network.DNS.Resolver as DNS
import Network.DNS.Types

----------------------------------------------------------------

{-|
  Resolving 'IPv4' by 'A'.
-}
lookupA :: Resolver -> Domain -> IO (Either DNSError [IPv4])
lookupA rlv dom = do
  erds <- DNS.lookup rlv dom A
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RDATA -> Either DNSError IPv4
    unTag (RD_A x) = Right x
    unTag _ = Left UnexpectedRDATA

{-|
  Resolving 'IPv6' by 'AAAA'.
-}
lookupAAAA :: Resolver -> Domain -> IO (Either DNSError [IPv6])
lookupAAAA rlv dom = do
  erds <- DNS.lookup rlv dom AAAA
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RDATA -> Either DNSError IPv6
    unTag (RD_AAAA x) = Right x
    unTag _ = Left UnexpectedRDATA

----------------------------------------------------------------

{-|
  Resolving 'Domain' and its preference by 'MX'.
-}
lookupMX :: Resolver -> Domain -> IO (Either DNSError [(Domain,Int)])
lookupMX rlv dom = do
  erds <- DNS.lookup rlv dom MX
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RDATA -> Either DNSError (Domain,Int)
    unTag (RD_MX pr dm) = Right (dm,pr)
    unTag _ = Left UnexpectedRDATA

{-|
  Resolving 'IPv4' by 'A' via 'MX'.
-}
lookupAviaMX :: Resolver -> Domain -> IO (Either DNSError [IPv4])
lookupAviaMX rlv dom = lookupXviaMX rlv dom (lookupA rlv)

{-|
  Resolving 'IPv6' by 'AAAA' via 'MX'.
-}
lookupAAAAviaMX :: Resolver -> Domain -> IO (Either DNSError [IPv6])
lookupAAAAviaMX rlv dom = lookupXviaMX rlv dom (lookupAAAA rlv)

lookupXviaMX :: Show a
             => Resolver
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

{-|
  Resolving 'Domain' by 'NS'.
-}
lookupNS :: Resolver -> Domain -> IO (Either DNSError [Domain])
lookupNS rlv dom = do
  erds <- DNS.lookup rlv dom NS
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RDATA -> Either DNSError Domain
    unTag (RD_NS dm) = Right dm
    unTag _ = Left UnexpectedRDATA

----------------------------------------------------------------

{-|
  Resolving 'String' by 'TXT'.
-}
lookupTXT :: Resolver -> Domain -> IO (Either DNSError [ByteString])
lookupTXT rlv dom = do
  erds <- DNS.lookup rlv dom TXT
  case erds of
    -- See lookupXviaMX for an explanation of this construct.
    Left err  -> return (Left err)
    Right rds -> return $ mapM unTag rds
  where
    unTag :: RDATA -> Either DNSError ByteString
    unTag (RD_TXT x) = Right x
    unTag _ = Left UnexpectedRDATA

----------------------------------------------------------------

{-|
  Resolving 'Domain' and its preference by 'PTR'.
-}
lookupPTR :: Resolver -> Domain -> IO (Either DNSError [Domain])
lookupPTR rlv dom = toPTR <$> DNS.lookup rlv dom PTR
  where
    toPTR = fmap (map unTag)
    unTag (RD_PTR dm) = dm
    unTag _ = error "lookupPTR"

----------------------------------------------------------------

{-|
  Resolving 'Domain' and its preference by 'SRV'.
-}
lookupSRV :: Resolver -> Domain -> IO (Either DNSError [(Int,Int,Int,Domain)])
lookupSRV rlv dom = toSRV <$> DNS.lookup rlv dom SRV
  where
    toSRV = fmap (map unTag)
    unTag (RD_SRV pri wei prt dm) = (pri,wei,prt,dm)
    unTag _ = error "lookupSRV"
