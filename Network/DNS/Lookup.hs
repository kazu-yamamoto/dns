{-|
  Upper level DNS lookup functions.
-}

module Network.DNS.Lookup (
    lookupA, lookupAAAA
  , lookupMX, lookupAviaMX, lookupAAAAviaMX
  , lookupTXT
  ) where

import Control.Applicative
import Data.IP
import Data.Maybe
import Network.DNS.Types
import Network.DNS.Resolver as DNS

----------------------------------------------------------------

{-|
  Resolving 'IPv4' by 'A'.
-}
lookupA :: Resolver -> Domain -> IO (Maybe [IPv4])
lookupA rlv dom = toV4 <$> DNS.lookup rlv dom A
  where
    toV4 = maybe Nothing (Just . map unTag)
    unTag (RD_A x) = x
    unTag _ = error "lookupA"

{-|
  Resolving 'IPv6' by 'AAAA'.
-}
lookupAAAA :: Resolver -> Domain -> IO (Maybe [IPv6])
lookupAAAA rlv dom = toV6 <$> DNS.lookup rlv dom AAAA
  where
    toV6 = maybe Nothing (Just . map unTag)
    unTag (RD_AAAA x) = x
    unTag _ = error "lookupAAAA"

----------------------------------------------------------------

{-|
  Resolving 'Domain' and its preference by 'MX'.
-}
lookupMX :: Resolver -> Domain -> IO (Maybe [(Domain,Int)])
lookupMX rlv dom = toMX <$> DNS.lookup rlv dom MX
  where
    toMX = maybe Nothing (Just . map unTag)
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

lookupXviaMX :: Resolver -> Domain -> (Domain -> IO (Maybe [a])) -> IO (Maybe [a])
lookupXviaMX rlv dom func = do
    mdps <- lookupMX rlv dom
    maybe (return Nothing) lookup' mdps
  where
    lookup' dps = do
        as <- catMaybes <$> mapM func (map fst dps)
        case as of
          []  -> return Nothing
          ass -> return $ Just (concat ass)

----------------------------------------------------------------

{-|
  Resolving 'String' by 'TXT'.
-}
lookupTXT :: Resolver -> Domain -> IO (Maybe [String])
lookupTXT rlv dom = toTXT <$> DNS.lookup rlv dom TXT
  where
    toTXT = maybe Nothing (Just . map unTag)
    unTag (RD_TXT x) = x
    unTag _ = error "lookupTXT"
