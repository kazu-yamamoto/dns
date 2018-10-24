module Network.DNS.Memo where

import qualified Control.Reaper as R
import qualified Data.ByteString as B
import Data.Hourglass (Elapsed)
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as PSQ
import Time.System (timeCurrent)

import Network.DNS.Imports
import Network.DNS.Types

data Section = Answer | Authority deriving (Eq, Ord, Show)

type Key = (ByteString
           ,TYPE)
type Prio = Elapsed

type Entry = Either DNSError [RData]

type DB = OrdPSQ Key Prio Entry

type Cache = R.Reaper DB (Key,Prio,Entry)

newCache :: Int -> IO Cache
newCache delay = R.mkReaper R.defaultReaperSettings {
    R.reaperEmpty  = PSQ.empty
  , R.reaperCons   = \(k, tim, v) psq -> PSQ.insert k tim v psq
  , R.reaperAction = prune
  , R.reaperDelay  = delay * 1000000
  , R.reaperNull   = PSQ.null
  }

lookupCache :: Key -> Cache -> IO (Maybe (Prio, Entry))
lookupCache key reaper = PSQ.lookup key <$> R.reaperRead reaper

insertCache :: Key -> Prio -> Entry -> Cache -> IO ()
insertCache (dom,typ) tim ent0 reaper = R.reaperAdd reaper (key,tim,ent)
  where
    key = (B.copy dom,typ)
    ent = case ent0 of
      l@(Left _)  -> l
      (Right rds) -> Right $ map copy rds

-- Theoretically speaking, atMostView itself is good enough for pruning.
-- But auto-update assumes a list based db which does not provide atMost
-- functions. So, we need to do this redundant way.
prune :: DB -> IO (DB -> DB)
prune oldpsq = do
    tim <- timeCurrent
    let (_, pruned) = PSQ.atMostView tim oldpsq
    return $ \newpsq -> foldl' ins pruned $ PSQ.toList newpsq
  where
    ins psq (k,p,v) = PSQ.insert k p v psq

copy :: RData -> RData
copy r@(RD_A _)           = r
copy (RD_NS dom)          = RD_NS $ B.copy dom
copy (RD_CNAME dom)       = RD_CNAME $ B.copy dom
copy (RD_SOA mn mr a b c d e) = RD_SOA (B.copy mn) (B.copy mr) a b c d e
copy (RD_PTR dom)         = RD_PTR $ B.copy dom
copy RD_NULL              = RD_NULL
copy (RD_MX prf dom)      = RD_MX prf $ B.copy dom
copy (RD_TXT txt)         = RD_TXT $ B.copy txt
copy r@(RD_AAAA _)        = r
copy (RD_SRV a b c dom)   = RD_SRV a b c $ B.copy dom
copy (RD_DNAME dom)       = RD_DNAME $ B.copy dom
copy (RD_OPT od)          = RD_OPT $ map copyOData od
copy (RD_DS t a dt dv)    = RD_DS t a dt $ B.copy dv
copy (RD_DNSKEY f p a k)  = RD_DNSKEY f p a $ B.copy k
copy (RD_TLSA a b c dgst) = RD_TLSA a b c $ B.copy dgst
copy (RD_NSEC3PARAM a b c salt) = RD_NSEC3PARAM a b c $ B.copy salt
copy (UnknownRData is)    = UnknownRData $ B.copy is

copyOData :: OData -> OData
copyOData (OD_ECSgeneric family srcBits scpBits bs) =
    OD_ECSgeneric family srcBits scpBits $ B.copy bs
copyOData (OD_NSID nsid) = OD_NSID $ B.copy nsid
copyOData (UnknownOData c b)        = UnknownOData c $ B.copy b

-- No copying required for the rest, but avoiding a wildcard pattern match
-- so that if more option types are added in the future, the compiler will
-- complain about a partial function.
--
copyOData o@OD_ClientSubnet {} = o
copyOData o@OD_DAU {} = o
copyOData o@OD_DHU {} = o
copyOData o@OD_N3U {} = o
