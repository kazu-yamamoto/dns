{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.DNS.Types.Op (
    QueryControls(..)
  , FlagOp(..)
  , ODataOp(..)
  , defaultQuery
  , makeQuery
  , makeEmptyQuery
  , rdFlag
  , adFlag
  , cdFlag
  , ednsEnabled
  , ednsSetVersion
  , ednsSetUdpSize
  , doFlag
  , ednsSetOptions
  , defaultResponse
  , makeResponse
  ) where

import qualified Data.Semigroup as Sem

import Network.DNS.Imports
import Network.DNS.Types.EDNS
import Network.DNS.Types.Message

----------------------------------------------------------------

-- | Boolean flag operations. These form a 'Monoid'.  When combined via
-- `mappend`, as with function composition, the left-most value has
-- the last say.
--
-- >>> mempty :: FlagOp
-- FlagKeep
-- >>> FlagSet <> mempty
-- FlagSet
-- >>> FlagClear <> FlagSet <> mempty
-- FlagClear
-- >>> FlagReset <> FlagClear <> FlagSet <> mempty
-- FlagReset
data FlagOp = FlagSet   -- ^ Set the flag to 1
            | FlagClear -- ^ Clear the flag to 0
            | FlagReset -- ^ Reset the flag to its default value
            | FlagKeep  -- ^ Leave the flag unchanged
            deriving (Eq, Show)

-- $
-- Test associativity of the semigroup operation:
--
-- >>> let ops = [FlagSet, FlagClear, FlagReset, FlagKeep]
-- >>> foldl (&&) True [(a<>b)<>c == a<>(b<>c) | a <- ops, b <- ops, c <- ops]
-- True
--
instance Sem.Semigroup FlagOp where
    FlagKeep <> op = op
    op       <> _  = op

instance Monoid FlagOp where
    mempty = FlagKeep
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

-- | We don't show options left at their default value.
--
_skipDefault :: String
_skipDefault = ""

-- | Show non-default flag values
--
_showFlag :: String -> FlagOp -> String
_showFlag nm FlagSet   = nm ++ ":1"
_showFlag nm FlagClear = nm ++ ":0"
_showFlag _  FlagReset = _skipDefault
_showFlag _  FlagKeep  = _skipDefault

-- | Combine a list of options for display, skipping default values
--
_showOpts :: [String] -> String
_showOpts os = intercalate "," $ filter (/= _skipDefault) os

----------------------------------------------------------------

-- | Control over query-related DNS header flags. As with function composition,
-- the left-most value has the last say.
--
data HeaderControls = HeaderControls
    { rdBit :: !FlagOp
    , adBit :: !FlagOp
    , cdBit :: !FlagOp
    }
    deriving (Eq)

instance Sem.Semigroup HeaderControls where
    (HeaderControls rd1 ad1 cd1) <> (HeaderControls rd2 ad2 cd2) =
        HeaderControls (rd1 <> rd2) (ad1 <> ad2) (cd1 <> cd2)

instance Monoid HeaderControls where
    mempty = HeaderControls FlagKeep FlagKeep FlagKeep
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

instance Show HeaderControls where
    show (HeaderControls rd ad cd) =
        _showOpts
             [ _showFlag "rd" rd
             , _showFlag "ad" ad
             , _showFlag "cd" cd ]

----------------------------------------------------------------

-- | The default EDNS Option list is empty.  We define two operations, one to
-- prepend a list of options, and another to set a specific list of options.
--
data ODataOp = ODataAdd [OData] -- ^ Add the specified options to the list.
             | ODataSet [OData] -- ^ Set the option list as specified.
             deriving (Eq)

-- | Since any given option code can appear at most once in the list, we
-- de-duplicate by the OPTION CODE when combining lists.
--
_odataDedup :: ODataOp -> [OData]
_odataDedup op =
    nubBy ((==) `on` odataToOptCode) $
        case op of
            ODataAdd os -> os
            ODataSet os -> os

-- $
-- Test associativity of the OData semigroup operation:
--
-- >>> let ip1 = IPv4 $ read "127.0.0.0"
-- >>> let ip2 = IPv4 $ read "192.0.2.0"
-- >>> let cs1 = OD_ClientSubnet 8 0 ip1
-- >>> let cs2 = OD_ClientSubnet 24 0 ip2
-- >>> let cs3 = OD_ECSgeneric 0 24 0 "foo"
-- >>> let dau1 = OD_DAU [3,5,7,8]
-- >>> let dau2 = OD_DAU [13,14]
-- >>> let dhu1 = OD_DHU [1,2]
-- >>> let dhu2 = OD_DHU [3,4]
-- >>> let nsid = OD_NSID ""
-- >>> let ops1 = [ODataAdd [dau1, dau2, cs1], ODataAdd [dau2, cs2, dhu1]]
-- >>> let ops2 = [ODataSet [], ODataSet [dhu2, cs3], ODataSet [nsid]]
-- >>> let ops = ops1 ++ ops2
-- >>> foldl (&&) True [(a<>b)<>c == a<>(b<>c) | a <- ops, b <- ops, c <- ops]
-- True

instance Sem.Semigroup ODataOp where
    ODataAdd as <> ODataAdd bs = ODataAdd $ as ++ bs
    ODataAdd as <> ODataSet bs = ODataSet $ as ++ bs
    ODataSet as <> _ = ODataSet as

instance Monoid ODataOp where
    mempty = ODataAdd []
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

----------------------------------------------------------------

-- | EDNS query controls.  When EDNS is disabled via @ednsEnabled FlagClear@,
-- all the other EDNS-related overrides have no effect.
--
-- >>> ednsHeader $ makeEmptyQuery $ ednsEnabled FlagClear <> doFlag FlagSet
-- NoEDNS
data EdnsControls = EdnsControls
    { extEn :: !FlagOp         -- ^ Enabled
    , extVn :: !(Maybe Word8)  -- ^ Version
    , extSz :: !(Maybe Word16) -- ^ UDP Size
    , extDO :: !FlagOp         -- ^ DNSSEC OK (DO) bit
    , extOd :: !ODataOp        -- ^ EDNS option list tweaks
    }
    deriving (Eq)

-- | Apply all the query flag overrides to 'defaultDNSFlags', returning the

instance Sem.Semigroup EdnsControls where
    (EdnsControls en1 vn1 sz1 do1 od1) <> (EdnsControls en2 vn2 sz2 do2 od2) =
        EdnsControls (en1 <> en2) (vn1 <|> vn2) (sz1 <|> sz2)
                    (do1 <> do2) (od1 <> od2)

instance Monoid EdnsControls where
    mempty = EdnsControls FlagKeep Nothing Nothing FlagKeep mempty
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

instance Show EdnsControls where
    show (EdnsControls en vn sz d0 od) =
        _showOpts
            [ _showFlag "edns.enabled" en
            , _showWord "edns.version" vn
            , _showWord "edns.udpsize" sz
            , _showFlag "edns.dobit"   d0
            , _showOdOp "edns.options" $ map (show. odataToOptCode)
                                       $ _odataDedup od ]
      where
        _showWord :: Show a => String -> Maybe a -> String
        _showWord nm w = maybe _skipDefault (\s -> nm ++ ":" ++ show s) w

        _showOdOp :: String -> [String] -> String
        _showOdOp nm os = case os of
            [] -> ""
            _  -> nm ++ ":[" ++ intercalate "," os ++ "]"

----------------------------------------------------------------

-- | Query controls form a 'Monoid', as with function composition, the
-- left-most value has the last say.  The 'Monoid' is generated by two sets of
-- combinators, one that controls query-related DNS header flags, and another
-- that controls EDNS features.
--
-- The header flag controls are: 'rdFlag', 'adFlag' and 'cdFlag'.
--
-- The EDNS feature controls are: 'doFlag', 'ednsEnabled', 'ednsSetVersion',
-- 'ednsSetUdpSize' and 'ednsSetOptions'.  When EDNS is disabled, all the other
-- EDNS-related controls have no effect.
--
-- __Example:__ Disable DNSSEC checking on the server, and request signatures and
-- NSEC records, perhaps for your own independent validation.  The UDP buffer
-- size is set large, for use with a local loopback nameserver on the same host.
--
-- >>> :{
-- mconcat [ adFlag FlagClear
--         , cdFlag FlagSet
--         , doFlag FlagSet
--         , ednsSetUdpSize (Just 8192) -- IPv4 loopback server?
--         ]
-- :}
-- ad:0,cd:1,edns.udpsize:8192,edns.dobit:1
--
-- __Example:__ Use EDNS version 1 (yet to be specified), request nameserver
-- ids from the server, and indicate a client subnet of "192.0.2.1/24".
--
-- >>> :set -XOverloadedStrings
-- >>> let emptyNSID = ""
-- >>> let mask = 24
-- >>> let ipaddr = read "192.0.2.1"
-- >>> :{
-- mconcat [ ednsSetVersion (Just 1)
--         , ednsSetOptions (ODataAdd [OD_NSID emptyNSID])
--         , ednsSetOptions (ODataAdd [OD_ClientSubnet mask 0 ipaddr])
--         ]
-- :}
-- edns.version:1,edns.options:[NSID,ClientSubnet]

data QueryControls = QueryControls
    { qctlHeader :: !HeaderControls
    , qctlEdns   :: !EdnsControls
    }
    deriving (Eq)

instance Sem.Semigroup QueryControls where
    (QueryControls fl1 ex1) <> (QueryControls fl2 ex2) =
        QueryControls (fl1 <> fl2) (ex1 <> ex2)

instance Monoid QueryControls where
    mempty = QueryControls mempty mempty
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

instance Show QueryControls where
    show (QueryControls fl ex) = _showOpts [ show fl, show ex ]

----------------------------------------------------------------

-- | Generator of 'QueryControls' that adjusts the RD bit.
--
-- >>> rdFlag FlagClear
-- rd:0
rdFlag :: FlagOp -> QueryControls
rdFlag rd = mempty { qctlHeader = mempty { rdBit = rd } }

-- | Generator of 'QueryControls' that adjusts the AD bit.
--
-- >>> adFlag FlagSet
-- ad:1
adFlag :: FlagOp -> QueryControls
adFlag ad = mempty { qctlHeader = mempty { adBit = ad } }

-- | Generator of 'QueryControls' that adjusts the CD bit.
--
-- >>> cdFlag FlagSet
-- cd:1
cdFlag :: FlagOp -> QueryControls
cdFlag cd = mempty { qctlHeader = mempty { cdBit = cd } }

-- | Generator of 'QueryControls' that enables or disables EDNS support.
--   When EDNS is disabled, the rest of the 'EDNS' controls are ignored.
--
-- >>> ednsHeader $ makeEmptyQuery $ ednsEnabled FlagClear <> doFlag FlagSet
-- NoEDNS
ednsEnabled :: FlagOp -> QueryControls
ednsEnabled en = mempty { qctlEdns = mempty { extEn = en } }

-- | Generator of 'QueryControls' that adjusts the 'EDNS' version.
-- A value of 'Nothing' makes no changes, while 'Just' @v@ sets
-- the EDNS version to @v@.
--
-- >>> ednsSetVersion (Just 1)
-- edns.version:1
ednsSetVersion :: Maybe Word8 -> QueryControls
ednsSetVersion vn = mempty { qctlEdns = mempty { extVn = vn } }

-- | Generator of 'QueryControls' that adjusts the 'EDNS' UDP buffer size.
-- A value of 'Nothing' makes no changes, while 'Just' @n@ sets the EDNS UDP
-- buffer size to @n@.
--
-- >>> ednsSetUdpSize (Just 2048)
-- edns.udpsize:2048
ednsSetUdpSize :: Maybe Word16 -> QueryControls
ednsSetUdpSize sz = mempty { qctlEdns = mempty { extSz = sz } }

-- | Generator of 'QueryControls' that adjusts the 'EDNS' DnssecOk (DO) bit.
--
-- >>> doFlag FlagSet
-- edns.dobit:1
doFlag :: FlagOp -> QueryControls
doFlag d0 = mempty { qctlEdns = mempty { extDO = d0 } }

-- | Generator of 'QueryControls' that adjusts the list of 'EDNS' options.
--
-- >>> :set -XOverloadedStrings
-- >>> ednsSetOptions (ODataAdd [OD_NSID ""])
-- edns.options:[NSID]
ednsSetOptions :: ODataOp -> QueryControls
ednsSetOptions od = mempty { qctlEdns = mempty { extOd = od } }

----------------------------------------------------------------

-- | A 'DNSMessage' template for queries with default settings for
-- the message 'DNSHeader' and 'EDNSheader'.  This is the initial
-- query message state, before customization via 'QueryControls'.
--
defaultQuery :: DNSMessage
defaultQuery = DNSMessage {
    header = DNSHeader {
       identifier = 0
     , flags = defaultDNSFlags
     }
  , ednsHeader = EDNSheader defaultEDNS
  , question   = []
  , answer     = []
  , authority  = []
  , additional = []
  }

-- | Default response.  When responding to EDNS queries, the response must
-- either be an EDNS response, or else FormatErr must be returned.  The default
-- response message has EDNS disabled ('ednsHeader' set to 'NoEDNS'), it should
-- be updated as appropriate.
--
-- Do not explicitly add OPT RRs to the additional section, instead let the
-- encoder compute and add the OPT record based on the EDNS pseudo-header.
--
-- The 'RCODE' in the 'DNSHeader' should be set to the appropriate 12-bit
-- extended value, which will be split between the primary header and EDNS OPT
-- record during message encoding (low 4 bits in DNS header, high 8 bits in
-- EDNS OPT record).  See 'EDNSheader' for more details.
--
defaultResponse :: DNSMessage
defaultResponse = DNSMessage {
    header = DNSHeader {
       identifier = 0
     , flags = defaultDNSFlags {
              qOrR = QR_Response
            , authAnswer = True
            , recAvailable = True
            , authenData = False
       }
     }
  , ednsHeader = NoEDNS
  , question   = []
  , answer     = []
  , authority  = []
  , additional = []
  }

-- | A query template with 'QueryControls' overrides applied,
-- with just the 'Question' and query 'Identifier' remaining
-- to be filled in.
--
makeEmptyQuery :: QueryControls -- ^ Flag and EDNS overrides
               -> DNSMessage
makeEmptyQuery ctls = defaultQuery {
      header = header'
    , ednsHeader = queryEdns ehctls
    }
  where
    hctls = qctlHeader ctls
    ehctls = qctlEdns ctls
    header' = (header defaultQuery) { flags = queryDNSFlags hctls }

    -- | Apply the given 'FlagOp' to a default boolean value to produce the final
    -- setting.
    --
    applyFlag :: FlagOp -> Bool -> Bool
    applyFlag FlagSet   _ = True
    applyFlag FlagClear _ = False
    applyFlag _         v = v

    -- | Construct a list of 0 or 1 EDNS OPT RRs based on EdnsControls setting.
    --
    queryEdns :: EdnsControls -> EDNSheader
    queryEdns (EdnsControls en vn sz d0 od) =
        let d  = defaultEDNS
         in if en == FlagClear
            then NoEDNS
            else EDNSheader $ d { ednsVersion = fromMaybe (ednsVersion d) vn
                                , ednsUdpSize = fromMaybe (ednsUdpSize d) sz
                                , ednsDnssecOk = applyFlag d0 (ednsDnssecOk d)
                                , ednsOptions  = _odataDedup od
                                }

    -- | Apply all the query flag overrides to 'defaultDNSFlags', returning the
    -- resulting 'DNSFlags' suitable for making queries with the requested flag
    -- settings.  This is only needed if you're creating your own 'DNSMessage',
    -- the 'Network.DNS.LookupRaw.lookupRawCtl' function takes a 'QueryControls'
    -- argument and handles this conversion internally.
    --
    -- Default overrides can be specified in the resolver configuration by setting
    -- the 'Network.DNS.resolvQueryControls' field of the
    -- 'Network.DNS.Resolver.ResolvConf' argument to
    -- 'Network.DNS.Resolver.makeResolvSeed'.  These then apply to lookups via
    -- resolvers based on the resulting configuration, with the exception of
    -- 'Network.DNS.LookupRaw.lookupRawCtl' which takes an additional
    -- 'QueryControls' argument to augment the default overrides.
    --
    queryDNSFlags :: HeaderControls -> DNSFlags
    queryDNSFlags (HeaderControls rd ad cd) = d {
          recDesired = applyFlag rd $ recDesired d
        , authenData = applyFlag ad $ authenData d
        , chkDisable = applyFlag cd $ chkDisable d
        }
      where
        d = defaultDNSFlags

-- | Construct a complete query 'DNSMessage', by combining the 'defaultQuery'
-- template with the specified 'Identifier', and 'Question'.  The
-- 'QueryControls' can be 'mempty' to leave all header and EDNS settings at
-- their default values, or some combination of overrides.  A default set of
-- overrides can be enabled via the 'Network.DNS.Resolver.resolvQueryControls'
-- field of 'Network.DNS.Resolver.ResolvConf'.  Per-query overrides are
-- possible by using 'Network.DNS.LookupRaw.loookupRawCtl'.
--
makeQuery :: Identifier        -- ^ Crypto random request id
          -> Question          -- ^ Question name and type
          -> QueryControls     -- ^ Custom RD\/AD\/CD flags and EDNS settings
          -> DNSMessage
makeQuery idt q ctls = empqry {
      header = (header empqry) { identifier = idt }
    , question = [q]
    }
  where
    empqry = makeEmptyQuery ctls

-- | Construct a query response 'DNSMessage'.
makeResponse :: Identifier
             -> Question
             -> Answers
             -> DNSMessage
makeResponse idt q as = defaultResponse {
      header = header' { identifier = idt }
    , question = [q]
    , answer   = as
    }
  where
    header' = header defaultResponse
