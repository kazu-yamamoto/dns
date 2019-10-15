module Network.DNS.ZoneTransfer.Conduit where

import Conduit (ConduitT, MonadResource, bracketP, liftIO, yield)

import Network.DNS.Types
import Network.DNS.Types.Internal
import Network.DNS.ZoneTransfer

zoneTransferC :: MonadResource m
              => Resolver -> Domain -> ConduitT () ResourceRecord m ()
zoneTransferC rlv zone = bracketP (initiateZoneTransfer rlv zone) closeRRStream handle
  where handle rrst = liftIO (nextRecord rrst) >>= maybe (return ()) (\rr -> yield rr >> handle rrst)
