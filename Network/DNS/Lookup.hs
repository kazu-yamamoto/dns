{-|
  Upper level DNS lookup functions.
-}

module Network.DNS.Lookup (
    lookupA, lookupAAAA
  , lookupMX, lookupAviaMX, lookupAAAAviaMX
  , lookupTXT
  , lookupPTR
  , lookupSRV
  ) where

import Control.Applicative
import Data.ByteString (ByteString)
import Data.IP
import Data.Maybe
import Network.DNS.Resolver as DNS
import Network.DNS.Types

----------------------------------------------------------------

{-|
  Resolving 'IPv4' by 'A'.
-}
lookupA :: Resolver -> Domain -> IO (Maybe [IPv4])
lookupA rlv dom = toV4 <$> DNS.lookup rlv dom A
  where
    toV4 = fmap (map unTag)
    unTag (RD_A x) = x
    unTag _ = error "lookupA"

{-|
  Resolving 'IPv6' by 'AAAA'.
-}
lookupAAAA :: Resolver -> Domain -> IO (Maybe [IPv6])
lookupAAAA rlv dom = toV6 <$> DNS.lookup rlv dom AAAA
  where
    toV6 = fmap (map unTag)
    unTag (RD_AAAA x) = x
    unTag _ = error "lookupAAAA"

----------------------------------------------------------------

{-|
  Resolving 'Domain' and its preference by 'MX'.
-}
lookupMX :: Resolver -> Domain -> IO (Maybe [(Domain,Int)])
lookupMX rlv dom = toMX <$> DNS.lookup rlv dom MX
  where
    toMX = fmap (map unTag)
    unTag (RD_MX pr dm) = (dm,pr)
    unTag _ = error "lookupMX"

{-|
  Resolving 'IPv4' by 'A' via 'MX'.
-}
lookupAviaMX :: Resolver -> Domain -> IO (Maybe [IPv4])
lookupAviaMX rlv dom = lookupXviaMX rlv dom (lookupA rlv)

{-|
  Resolving 'IPv6' by 'AAAA' via 'MX'.
-}
lookupAAAAviaMX :: Resolver -> Domain -> IO (Maybe [IPv6])
lookupAAAAviaMX rlv dom = lookupXviaMX rlv dom (lookupAAAA rlv)

lookupXviaMX :: Show a => Resolver -> Domain -> (Domain -> IO (Maybe [a])) -> IO (Maybe [a])
lookupXviaMX rlv dom func = do
    mdps <- lookupMX rlv dom
    maybe (return Nothing) lookup' mdps
  where
    lookup' dps = check . catMaybes <$> mapM (func . fst) dps
    check as = case as of
        []  -> Nothing
        ass -> Just (concat ass)

----------------------------------------------------------------

{-|
  Resolving 'String' by 'TXT'.
-}
lookupTXT :: Resolver -> Domain -> IO (Maybe [ByteString])
lookupTXT rlv dom = toTXT <$> DNS.lookup rlv dom TXT
  where
    toTXT = fmap (map unTag)
    unTag (RD_TXT x) = x
    unTag _ = error "lookupTXT"

----------------------------------------------------------------

{-|
  Resolving 'Domain' and its preference by 'PTR'.
-}
lookupPTR :: Resolver -> Domain -> IO (Maybe [Domain])
lookupPTR rlv dom = toPTR <$> DNS.lookup rlv dom PTR
  where
    toPTR = fmap (map unTag)
    unTag (RD_PTR dm) = dm
    unTag _ = error "lookupPTR"

----------------------------------------------------------------

{-|
  Resolving 'Domain' and its preference by 'SRV'.
-}
lookupSRV :: Resolver -> Domain -> IO (Maybe [(Int,Int,Int,Domain)])
lookupSRV rlv dom = toSRV <$> DNS.lookup rlv dom SRV
  where
    toSRV = fmap (map unTag)
    unTag (RD_SRV pri wei prt dm) = (pri,wei,prt,dm)
    unTag _ = error "lookupSRV"
