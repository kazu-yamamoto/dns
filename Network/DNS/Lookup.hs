module Network.DNS.Lookup where

import Control.Applicative
import Data.IP
import Network.DNS.Types
import Network.DNS.Resolver as DNS

lookupA :: Resolver -> Domain -> IO (Maybe [IPv4])
lookupA rlv dom = toV4 <$> DNS.lookup rlv dom A
  where
    toV4 = maybe Nothing (Just . map unTag)
    unTag (RD_A x) = x
    unTag _ = error "lookupA"

lookupAAAA :: Resolver -> Domain -> IO (Maybe [IPv6])
lookupAAAA rlv dom = toV6 <$> DNS.lookup rlv dom AAAA
  where
    toV6 = maybe Nothing (Just . map unTag)
    unTag (RD_AAAA x) = x
    unTag _ = error "lookupAAAA"

lookupAviaMX :: Resolver -> Domain -> IO (Maybe [IPv4])
lookupAviaMX = undefined

lookupAAAAviaMX :: Resolver -> Domain -> IO (Maybe [IPv6])
lookupAAAAviaMX = undefined

lookupTXT :: Resolver -> Domain -> IO (Maybe [String])
lookupTXT rlv dom = toTXT <$> DNS.lookup rlv dom TXT
  where
    toTXT = maybe Nothing (Just . map unTag)
    unTag (RD_TXT x) = x
    unTag _ = error "lookupTXT"
