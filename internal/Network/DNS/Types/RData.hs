{-# LANGUAGE OverloadedStrings #-}

module Network.DNS.Types.RData where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BS
import Data.Char (intToDigit)
import Data.IP (IPv4, IPv6)

import Network.DNS.Imports
import Network.DNS.Types.Base
import Network.DNS.Types.EDNS
import Network.DNS.Types.SIG

-- | Raw data format for each type.
data RData = RD_A IPv4           -- ^ IPv4 address
           | RD_NS Domain        -- ^ An authoritative name serve
           | RD_CNAME Domain     -- ^ The canonical name for an alias
           | RD_SOA Domain Mailbox Word32 Word32 Word32 Word32 Word32
                                 -- ^ Marks the start of a zone of authority
           | RD_NULL ByteString  -- ^ NULL RR (EXPERIMENTAL, RFC1035).
           | RD_PTR Domain       -- ^ A domain name pointer
           | RD_MX Word16 Domain -- ^ Mail exchange
           | RD_TXT ByteString   -- ^ Text strings
           | RD_RP Mailbox Domain -- ^ Responsible Person (RFC1183)
           | RD_AAAA IPv6        -- ^ IPv6 Address
           | RD_SRV Word16 Word16 Word16 Domain
                                 -- ^ Server Selection (RFC2782)
           | RD_DNAME Domain     -- ^ DNAME (RFC6672)
           | RD_OPT [OData]      -- ^ OPT (RFC6891)
           | RD_DS Word16 Word8 Word8 ByteString -- ^ Delegation Signer (RFC4034)
           | RD_RRSIG RDREP_RRSIG  -- ^ DNSSEC signature
           | RD_NSEC Domain [TYPE] -- ^ DNSSEC denial of existence NSEC record
           | RD_DNSKEY Word16 Word8 Word8 ByteString
                                 -- ^ DNSKEY (RFC4034)
           | RD_NSEC3 Word8 Word8 Word16 ByteString ByteString [TYPE]
                                 -- ^ DNSSEC hashed denial of existence (RFC5155)
           | RD_NSEC3PARAM Word8 Word8 Word16 ByteString
                                 -- ^ NSEC3 zone parameters (RFC5155)
           | RD_TLSA Word8 Word8 Word8 ByteString
                                 -- ^ TLSA (RFC6698)
           | RD_CDS Word16 Word8 Word8 ByteString
                                 -- ^ Child DS (RFC7344)
           | RD_CDNSKEY Word16 Word8 Word8 ByteString
                                 -- ^ Child DNSKEY (RFC7344)
           --RD_CSYNC
           | UnknownRData ByteString   -- ^ Unknown resource data
    deriving (Eq, Ord)

instance Show RData where
  show rd = case rd of
      RD_A                  address -> show address
      RD_NS                 nsdname -> showDomain nsdname
      RD_CNAME                cname -> showDomain cname
      RD_SOA          a b c d e f g -> showSOA a b c d e f g
      RD_NULL                 bytes -> showOpaque bytes
      RD_PTR               ptrdname -> showDomain ptrdname
      RD_MX               pref exch -> showMX pref exch
      RD_TXT             textstring -> showTXT textstring
      RD_RP              mbox dname -> showRP mbox dname
      RD_AAAA               address -> show address
      RD_SRV        pri wei prt tgt -> showSRV pri wei prt tgt
      RD_DNAME               target -> showDomain target
      RD_OPT                options -> show options
      RD_DS          tag alg dalg d -> showDS tag alg dalg d
      RD_RRSIG                 rrsig -> show rrsig
      RD_NSEC            next types -> showNSEC next types
      RD_DNSKEY             f p a k -> showDNSKEY f p a k
      RD_NSEC3      a f i s h types -> showNSEC3 a f i s h types
      RD_NSEC3PARAM         a f i s -> showNSEC3PARAM a f i s
      RD_TLSA               u s m d -> showTLSA u s m d
      RD_CDS         tag alg dalg d -> showDS tag alg dalg d
      RD_CDNSKEY            f p a k -> showDNSKEY f p a k
      UnknownRData            bytes -> showOpaque bytes
    where
      showSalt ""    = "-"
      showSalt salt  = _b16encode salt
      showDomain = BS.unpack
      showSOA mname rname serial refresh retry expire minttl =
          showDomain mname ++ " " ++ showDomain rname ++ " " ++
          show serial ++ " " ++ show refresh ++ " " ++
          show retry ++ " " ++ show expire ++ " " ++ show minttl
      showMX preference exchange =
          show preference ++ " " ++ showDomain exchange
      showTXT bs = '"' : B.foldr dnsesc ['"'] bs
        where
          c2w = fromIntegral . fromEnum
          w2c = toEnum . fromIntegral
          doubleQuote = c2w '"'
          backSlash   = c2w '\\'
          dnsesc c s
              | c == doubleQuote   = '\\' : w2c c : s
              | c == backSlash     = '\\' : w2c c : s
              | c >= 32 && c < 127 =        w2c c : s
              | otherwise          = '\\' : ddd c   s
          ddd c s =
              let (q100, r100) = divMod (fromIntegral c) 100
                  (q10, r10) = divMod r100 10
               in intToDigit q100 : intToDigit q10 : intToDigit r10 : s
      showRP mbox dname = showDomain mbox ++ " " ++ showDomain dname
      showSRV priority weight port target =
          show priority ++ " " ++ show weight ++ " " ++
          show port ++ " " ++ BS.unpack target
      showDS keytag alg digestType digest =
          show keytag ++ " " ++ show alg ++ " " ++
          show digestType ++ " " ++ _b16encode digest
      showNSEC next types =
          unwords $ showDomain next : map show types
      showDNSKEY flags protocol alg key =
          show flags ++ " " ++ show protocol ++ " " ++
          show alg ++ " " ++ _b64encode key
      -- | <https://tools.ietf.org/html/rfc5155#section-3.2>
      showNSEC3 hashalg flags iterations salt nexthash types =
          unwords $ show hashalg : show flags : show iterations :
                    showSalt salt : _b32encode nexthash : map show types
      showNSEC3PARAM hashAlg flags iterations salt =
          show hashAlg ++ " " ++ show flags ++ " " ++
          show iterations ++ " " ++ showSalt salt
      showTLSA usage selector mtype digest =
          show usage ++ " " ++ show selector ++ " " ++
          show mtype ++ " " ++ _b16encode digest
      -- | Opaque RData: <https://tools.ietf.org/html/rfc3597#section-5>
      showOpaque bs = unwords ["\\#", show (BS.length bs), _b16encode bs]
