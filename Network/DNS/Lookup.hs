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
lookupA rlv dom = toV4 <$> DNS.lookup rlv dom A
  where
    toV4 = fmap (map unTag)
    unTag (RD_A x) = x
    unTag _ = error "lookupA"

{-|
  Resolving 'IPv6' by 'AAAA'.
-}
lookupAAAA :: Resolver -> Domain -> IO (Either DNSError [IPv6])
lookupAAAA rlv dom = toV6 <$> DNS.lookup rlv dom AAAA
  where
    toV6 = fmap (map unTag)
    unTag (RD_AAAA x) = x
    unTag _ = error "lookupAAAA"

----------------------------------------------------------------

{-|
  Resolving 'Domain' and its preference by 'MX'.
-}
lookupMX :: Resolver -> Domain -> IO (Either DNSError [(Domain,Int)])
lookupMX rlv dom = toMX <$> DNS.lookup rlv dom MX
  where
    toMX = fmap (map unTag)
    unTag (RD_MX pr dm) = (dm,pr)
    unTag _ = error "lookupMX"

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
lookupNS rlv dom = toNS <$> DNS.lookup rlv dom NS
  where
    toNS = fmap (map unTag)
    unTag (RD_NS dm) = dm
    unTag _ = error "lookupNS"

----------------------------------------------------------------

{-|
  Resolving 'String' by 'TXT'.
-}
lookupTXT :: Resolver -> Domain -> IO (Either DNSError [ByteString])
lookupTXT rlv dom = toTXT <$> DNS.lookup rlv dom TXT
  where
    toTXT = fmap (map unTag)
    unTag (RD_TXT x) = x
    unTag _ = error "lookupTXT"

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
