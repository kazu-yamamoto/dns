{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TransformListComp #-}

module Network.DNS.Types.Sec (
    RD_RRSIG(..)
  , RD_DS(..)
  , RD_NSEC(..)
  , RD_DNSKEY(..)
  , RD_NSEC3(..)
  , RD_NSEC3PARAM(..)
  , RD_CDS(..)
  , RD_CDNSKEY(..)
  , getTYPE
  , dnsTime
  ) where

import qualified Data.ByteString.Char8 as BS
import qualified Data.Hourglass as H
import GHC.Exts (the, groupWith)

import Network.DNS.Imports
import Network.DNS.StateBinary
import Network.DNS.Types.Base
import Network.DNS.Types.RData

----------------------------------------------------------------

-- | DNSSEC signature
--
-- As noted in
-- <https://tools.ietf.org/html/rfc4034#section-3.1.5 Section 3.1.5 of RFC 4034>
-- the RRsig inception and expiration times use serial number arithmetic.  As a
-- result these timestamps /are not/ pure values, their meaning is
-- time-dependent!  They depend on the present time and are both at most
-- approximately +\/-68 years from the present.  This ambiguity is not a
-- problem because cached RRSIG records should only persist a few days,
-- signature lifetimes should be *much* shorter than 68 years, and key rotation
-- should result any misconstrued 136-year-old signatures fail to validate.
-- This also means that the interpretation of a time that is exactly half-way
-- around the clock at @now +\/-0x80000000@ is not important, the signature
-- should never be valid.
--
-- The upshot for us is that we need to convert these *impure* relative values
-- to pure absolute values at the moment they are received from from the network
-- (or read from files, ... in some impure I/O context), and convert them back to
-- 32-bit values when encoding.  Therefore, the constructor takes absolute
-- 64-bit representations of the inception and expiration times.
--
-- The 'dnsTime' function performs the requisite conversion.
--
data RD_RRSIG = RD_RRSIG {
    rrsigType       :: !TYPE       -- ^ RRtype of RRset signed
  , rrsigKeyAlg     :: !Word8      -- ^ DNSKEY algorithm
  , rrsigNumLabels  :: !Word8      -- ^ Number of labels signed
  , rrsigTTL        :: !Word32     -- ^ Maximum origin TTL
  , rrsigExpiration :: !Int64      -- ^ Time last valid
  , rrsigInception  :: !Int64      -- ^ Time first valid
  , rrsigKeyTag     :: !Word16     -- ^ Signing key tag
  , rrsigZone       :: !Domain     -- ^ Signing domain
  , rrsigValue      :: !ByteString -- ^ Opaque signature
  } deriving (Eq, Ord)

instance ResourceData RD_RRSIG where
    encodeResourceData = \RD_RRSIG{..} ->
      mconcat [ put16 $ fromTYPE rrsigType
              , put8    rrsigKeyAlg
              , put8    rrsigNumLabels
              , put32   rrsigTTL
              , put32 $ fromIntegral rrsigExpiration
              , put32 $ fromIntegral rrsigInception
              , put16   rrsigKeyTag
              , putDomain rrsigZone
              , putByteString rrsigValue
              ]
    decodeResourceData = \_ lim -> do
        -- The signature follows a variable length zone name
        -- and occupies the rest of the RData.  Simplest to
        -- checkpoint the position at the start of the RData,
        -- and after reading the zone name, and subtract that
        -- from the RData length.
        --
        end <- rdataEnd lim
        typ <- getTYPE
        alg <- get8
        cnt <- get8
        ttl <- get32
        tex <- getDnsTime
        tin <- getDnsTime
        tag <- get16
        dom <- getDomain -- XXX: Enforce no compression?
        pos <- getPosition
        val <- getNByteString $ end - pos
        return $ RD_RRSIG typ alg cnt ttl tex tin tag dom val
      where
        getDnsTime   = do
            tnow <- getAtTime
            tdns <- get32
            return $ dnsTime tdns tnow
    copyResourceData r@RD_RRSIG{..} =
        r { rrsigZone = BS.copy rrsigZone
          , rrsigValue = BS.copy rrsigValue }

instance Show RD_RRSIG where
    show RD_RRSIG{..} =
        unwords [ show rrsigType
                , show rrsigKeyAlg
                , show rrsigNumLabels
                , show rrsigTTL
                , showTime rrsigExpiration
                , showTime rrsigInception
                , show rrsigKeyTag
                , BS.unpack rrsigZone
                , _b64encode rrsigValue
                ]
      where
        showTime :: Int64 -> String
        showTime t = H.timePrint fmt $ H.Elapsed $ H.Seconds t
          where
            fmt = [ H.Format_Year4, H.Format_Month2, H.Format_Day2
                  , H.Format_Hour,  H.Format_Minute, H.Format_Second ]

----------------------------------------------------------------

-- | Delegation Signer (RFC4034)
data RD_DS = RD_DS {
    dsKeyTag     :: Word16
  , dsAlgorithm  :: Word8
  , dsDigestType :: Word8
  , dsDigest     :: ByteString
  } deriving (Eq)

instance ResourceData RD_DS where
    encodeResourceData = \RD_DS{..} ->
        mconcat [ put16 dsKeyTag
                , put8 dsAlgorithm
                , put8 dsDigestType
                , putByteString dsDigest
                ]
    decodeResourceData = \_ lim ->
        RD_DS <$> get16
              <*> get8
              <*> get8
              <*> getNByteString (lim - 4)
    copyResourceData r@RD_DS{..} = r { dsDigest = BS.copy dsDigest }

instance Show RD_DS where
    show RD_DS{..} = show dsKeyTag     ++ " "
                  ++ show dsAlgorithm  ++ " "
                  ++ show dsDigestType ++ " "
                  ++ _b16encode dsDigest

----------------------------------------------------------------

-- | DNSSEC denial of existence NSEC record
data RD_NSEC = RD_NSEC {
    nsecNextDomain :: Domain
  , nsecTypes      :: [TYPE]
  } deriving (Eq)

instance ResourceData RD_NSEC where
    encodeResourceData = \RD_NSEC{..} ->
        putDomain nsecNextDomain <> putNsecTypes nsecTypes
    decodeResourceData = \_ len -> do
        end <- rdataEnd len
        dom <- getDomain
        pos <- getPosition
        RD_NSEC dom <$> getNsecTypes (end - pos)
    copyResourceData r@RD_NSEC{..} =
        r { nsecNextDomain = BS.copy nsecNextDomain }

instance Show RD_NSEC where
    show RD_NSEC{..} =
        unwords $ showDomain nsecNextDomain : map show nsecTypes

----------------------------------------------------------------

-- | DNSKEY (RFC4034)
data RD_DNSKEY = RD_DNSKEY {
    dnskeyFlags     :: Word16
  , dnskeyProtocol  :: Word8
  , dnskeyAlgorithm :: Word8
  , dnskeyPublicKey :: ByteString
  } deriving (Eq)

instance ResourceData RD_DNSKEY where
    encodeResourceData = \RD_DNSKEY{..} ->
        mconcat [ put16 dnskeyFlags
                , put8  dnskeyProtocol
                , put8  dnskeyAlgorithm
                , putByteString dnskeyPublicKey
                ]
    decodeResourceData = \_ len ->
        RD_DNSKEY <$> get16
                  <*> get8
                  <*> get8
                  <*> getNByteString (len - 4)
    copyResourceData r@RD_DNSKEY{..} =
        r { dnskeyPublicKey = BS.copy dnskeyPublicKey }

-- <https://tools.ietf.org/html/rfc5155#section-3.2>
instance Show RD_DNSKEY where
    show RD_DNSKEY{..} = show dnskeyFlags     ++ " "
                      ++ show dnskeyProtocol  ++ " "
                      ++ show dnskeyAlgorithm ++ " "
                      ++ _b64encode dnskeyPublicKey

----------------------------------------------------------------

-- | DNSSEC hashed denial of existence (RFC5155)
data RD_NSEC3 = RD_NSEC3 {
    nsec3HashAlgorithm       :: Word8
  , nsec3Flags               :: Word8
  , nsec3Iterations          :: Word16
  , nsec3Salt                :: ByteString
  , nsec3NextHashedOwnerName :: ByteString
  , nsec3Types               :: [TYPE]
  } deriving (Eq)

instance ResourceData RD_NSEC3 where
    encodeResourceData = \RD_NSEC3{..} ->
        mconcat [ put8 nsec3HashAlgorithm
                , put8 nsec3Flags
                , put16 nsec3Iterations
                , putByteStringWithLength nsec3Salt
                , putByteStringWithLength nsec3NextHashedOwnerName
                , putNsecTypes nsec3Types
                ]
    decodeResourceData = \_ len -> do
        dend <- rdataEnd len
        halg <- get8
        flgs <- get8
        iter <- get16
        salt <- getInt8ByteString
        hash <- getInt8ByteString
        tpos <- getPosition
        RD_NSEC3 halg flgs iter salt hash <$> getNsecTypes (dend - tpos)
    copyResourceData r@RD_NSEC3{..} =
        r { nsec3Salt = BS.copy nsec3Salt
          , nsec3NextHashedOwnerName = BS.copy nsec3NextHashedOwnerName
          }

instance Show RD_NSEC3 where
    show RD_NSEC3{..} = unwords $ show nsec3HashAlgorithm
                                : show nsec3Flags
                                : show nsec3Iterations
                                : showSalt nsec3Salt
                                : _b32encode nsec3NextHashedOwnerName
                                : map show nsec3Types

----------------------------------------------------------------

-- | NSEC3 zone parameters (RFC5155)
data RD_NSEC3PARAM = RD_NSEC3PARAM {
    nsec3paramHashAlgorithm :: Word8
  , nsec3paramFlags         :: Word8
  , nsec3paramIterations    :: Word16
  , nsec3paramSalt          :: ByteString
  } deriving (Eq)

instance ResourceData RD_NSEC3PARAM where
    encodeResourceData = \RD_NSEC3PARAM{..} ->
        mconcat [ put8  nsec3paramHashAlgorithm
                , put8  nsec3paramFlags
                , put16 nsec3paramIterations
                , putByteStringWithLength nsec3paramSalt
                ]
    decodeResourceData = \_ _ ->
        RD_NSEC3PARAM <$> get8
                      <*> get8
                      <*> get16
                      <*> getInt8ByteString
    copyResourceData r@RD_NSEC3PARAM{..} =
        r { nsec3paramSalt = BS.copy nsec3paramSalt }

instance Show RD_NSEC3PARAM where
    show RD_NSEC3PARAM{..} = show nsec3paramHashAlgorithm ++ " "
                          ++ show nsec3paramFlags         ++ " "
                          ++ show nsec3paramIterations    ++ " "
                          ++ showSalt nsec3paramSalt

----------------------------------------------------------------

-- | Child DS (RFC7344)
newtype RD_CDS = RD_CDS RD_DS deriving (Eq)

instance ResourceData RD_CDS where
    encodeResourceData = \(RD_CDS ds) -> encodeResourceData ds
    decodeResourceData = \_ len -> RD_CDS <$> decodeResourceData (Proxy :: Proxy RD_DS) len
    copyResourceData = \(RD_CDS ds) -> RD_CDS $ copyResourceData ds

instance Show RD_CDS where
    show (RD_CDS ds) = show ds

----------------------------------------------------------------

-- | Child DNSKEY (RFC7344)
newtype RD_CDNSKEY = RD_CDNSKEY RD_DNSKEY deriving (Eq)

instance ResourceData RD_CDNSKEY where
    encodeResourceData = \(RD_CDNSKEY dnskey) -> encodeResourceData dnskey
    decodeResourceData = \_ len -> RD_CDNSKEY <$> decodeResourceData (Proxy :: Proxy RD_DNSKEY) len
    copyResourceData = \(RD_CDNSKEY dnskey) -> RD_CDNSKEY $ copyResourceData dnskey

instance Show RD_CDNSKEY where
    show (RD_CDNSKEY dnskey) = show dnskey

----------------------------------------------------------------

getTYPE :: SGet TYPE
getTYPE = toTYPE <$> get16

getInt8ByteString :: SGet ByteString
getInt8ByteString = getInt8 >>= getNByteString

-- | Given a 32-bit circle-arithmetic DNS time, and the current absolute epoch
-- time, return the epoch time corresponding to the DNS timestamp.
--
dnsTime :: Word32 -- ^ DNS circle-arithmetic timestamp
        -> Int64  -- ^ current epoch time
        -> Int64  -- ^ absolute DNS timestamp
dnsTime tdns tnow =
    let delta = tdns - fromIntegral tnow
     in if delta > 0x7FFFFFFF -- tdns is in the past?
           then tnow - (0x100000000 - fromIntegral delta)
           else tnow + fromIntegral delta

-- | Helper to find position of RData end, that is, the offset of the first
-- byte /after/ the current RData.
--
rdataEnd :: Int      -- ^ number of bytes left from current position
         -> SGet Int -- ^ end position
rdataEnd lim = (+) lim <$> getPosition

----------------------------------------------------------------

-- | Encode DNSSEC NSEC type bits
putNsecTypes :: [TYPE] -> SPut
putNsecTypes types = putTypeList $ map fromTYPE types
  where
    putTypeList :: [Word16] -> SPut
    putTypeList ts =
        mconcat [ putWindow (the top8) bot8 |
                  t <- ts,
                  let top8 = fromIntegral t `shiftR` 8,
                  let bot8 = fromIntegral t .&. 0xff,
                  then group by top8
                       using groupWith ]

    putWindow :: Int -> [Int] -> SPut
    putWindow top8 bot8s =
        let blks = maximum bot8s `shiftR` 3
         in putInt8 top8
            <> put8 (1 + fromIntegral blks)
            <> putBits 0 [ (the block, foldl' mergeBits 0 bot8) |
                           bot8 <- bot8s,
                           let block = bot8 `shiftR` 3,
                           then group by block
                                using groupWith ]
      where
        -- | Combine type bits in network bit order, i.e. bit 0 first.
        mergeBits acc b = setBit acc (7 - b.&.0x07)

    putBits :: Int -> [(Int, Word8)] -> SPut
    putBits _ [] = pure mempty
    putBits n ((block, octet) : rest) =
        putReplicate (block-n) 0
        <> put8 octet
        <> putBits (block + 1) rest

-- <https://tools.ietf.org/html/rfc4034#section-4.1>
-- Parse a list of NSEC type bitmaps
--
getNsecTypes :: Int -> SGet [TYPE]
getNsecTypes len = concat <$> sGetMany "NSEC type bitmap" len getbits
  where
    getbits = do
        window <- flip shiftL 8 <$> getInt8
        blocks <- getInt8
        when (blocks > 32) $
            failSGet $ "NSEC bitmap block too long: " ++ show blocks
        concatMap blkTypes. zip [window, window + 8..] <$> getNBytes blocks
      where
        blkTypes (bitOffset, byte) =
            [ toTYPE $ fromIntegral $ bitOffset + i |
              i <- [0..7], byte .&. bit (7-i) /= 0 ]
