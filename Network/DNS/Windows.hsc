{-# LANGUAGE CPP #-}

module Network.DNS.Windows where

import Data.Word (Word32)
import Foreign.C (peekCString, newCString)
import Foreign.Storable (Storable(..))
import Foreign.Ptr (Ptr)

#if __GLASGOW_HASKELL__ < 800
#let alignment t = "%lu", (unsigned long)offsetof(struct {char x__; t (y__); }, y__)
#endif

#include "dns.h"
data Dns_t = Dns_t {
    dnsError :: Word32
  , dnsAddresses :: String
  } deriving Show

foreign import ccall "getWindowsDefDnsServers" getWindowsDefDnsServers :: IO (Ptr Dns_t)

instance Storable Dns_t where
  alignment _ = #{alignment dns_t}
  sizeOf _    = #{size dns_t}
  peek ptr = do
    a <- #{peek dns_t, error} ptr
    b <- #{peek dns_t, dnsAddresses} ptr >>= peekCString
    return (Dns_t a b)
  poke ptr (Dns_t a b) = do
    #{poke dns_t, error} ptr a
    newCString b >>= #{poke dns_t, dnsAddresses} ptr
