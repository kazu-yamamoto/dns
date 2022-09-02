{-# LANGUAGE RecordWildCards #-}

module Network.DNS.Types.SIG where

import qualified Data.ByteString.Char8 as BS
import qualified Data.Hourglass as H

import Network.DNS.Imports
import Network.DNS.Types.Base

----------------------------------------------------------------

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

-- | RRSIG representation.
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
data RDREP_RRSIG = RDREP_RRSIG
    { rrsigType       :: !TYPE       -- ^ RRtype of RRset signed
    , rrsigKeyAlg     :: !Word8      -- ^ DNSKEY algorithm
    , rrsigNumLabels  :: !Word8      -- ^ Number of labels signed
    , rrsigTTL        :: !Word32     -- ^ Maximum origin TTL
    , rrsigExpiration :: !Int64      -- ^ Time last valid
    , rrsigInception  :: !Int64      -- ^ Time first valid
    , rrsigKeyTag     :: !Word16     -- ^ Signing key tag
    , rrsigZone       :: !Domain     -- ^ Signing domain
    , rrsigValue      :: !ByteString -- ^ Opaque signature
    }
    deriving (Eq, Ord)

instance Show RDREP_RRSIG where
    show RDREP_RRSIG{..} = unwords
        [ show rrsigType
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

