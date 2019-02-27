{-# LANGUAGE OverloadedStrings #-}

module Network.DNS.ZoneTransfer (
    RRStream
  , initiateZoneTransfer
  , nextRecord
  , closeRRStream
  ) where

import qualified Data.ByteString.Char8 as BS
import           Data.IORef            (IORef, newIORef, readIORef, writeIORef)
import qualified Data.List.NonEmpty    as NE
import           Data.Maybe            (fromMaybe)
import           Network.Socket        (AddrInfo, Socket, addrAddress, close,
                                        connect)

import Network.DNS.IO
import Network.DNS.Transport
import Network.DNS.Types
import Network.DNS.Types.Internal

data RRStream = RRStream
  { socket    :: Socket
  , timeout   :: Int
  , responses :: IORef AXFRResponses
  }

data AXFRResponses = AXFRResponses
  { receivedLast :: Bool
  , rrsInLatest  :: [ResourceRecord]
  }

initiateZoneTransfer :: Resolver -> Domain -> IO RRStream
initiateZoneTransfer rlv zone = do
  -- FIXME check for illegal domain
  let gen = NE.head $ genIds rlv
      seed = resolvseed rlv
      nss = NE.head $ nameservers seed
      conf = resolvconf seed
      ctls = resolvQueryControls conf
      tm = resolvTimeout conf

  ref <- newIORef $ AXFRResponses False []
  -- FIXME wrap with timeout
  -- FIXME check the first message is SOA
  vc <- axfrConnect gen nss zone ctls
  let rrst = RRStream vc tm ref
  receiveOneMessage rrst
  return rrst

nextRecord :: RRStream -> IO (Maybe ResourceRecord)
nextRecord rrst = do
  resps <- readIORef $ responses rrst
  case rrsInLatest resps of
    (x:xs) -> do
      let new = AXFRResponses (receivedLast resps) xs
      writeIORef (responses rrst) new
      return (Just x)
    [] -> do
      if receivedLast resps
      then return Nothing
      else do
        receiveOneMessage rrst
        nextRecord rrst

closeRRStream :: RRStream -> IO ()
closeRRStream = close . socket

receiveOneMessage :: RRStream -> IO ()
receiveOneMessage rrst = do
  -- FIXME wrap timeout
  msg <- receiveVC $ socket rrst
  let isLast = (rrtype . last . answer) msg == SOA
      new = AXFRResponses (isLast) (answer msg)
  writeIORef (responses rrst) new

axfrConnect :: IO Identifier -> AddrInfo -> Domain -> QueryControls -> IO Socket
axfrConnect gen ai zone ctls = do
  let addr = addrAddress ai
  sock <- tcpOpen addr
  ident <- gen
  let dottedZone = fromMaybe zone (BS.stripSuffix "." zone) <> "."
      q = Question dottedZone AXFR
      qry = encodeQuestion ident q ctls
  connect sock addr
  sendVC sock qry
  return sock
