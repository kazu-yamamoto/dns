{-# LANGUAGE OverloadedStrings #-}

module DecodeSpec where

import Data.ByteString.Internal (ByteString(..), unsafeCreate)
import qualified Data.ByteString.Lazy as BL
import Data.Word8
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (peek, poke, peekByteOff)
import Network.DNS.Decode
import Network.DNS.Encode
import Test.Hspec

----------------------------------------------------------------

test_doublePointer :: BL.ByteString
test_doublePointer = "f7eb8500000100010007000404736563330561706e696303636f6d0000010001c00c0001000100001c200004ca0c1c8cc0110002000100001c20000f036e73310561706e6963036e657400c0300002000100001c200006036e7333c040c0300002000100001c200006036e7334c040c0300002000100001c20001004736563310561706e696303636f6d00c0300002000100001c20001704736563310761757468646e730472697065036e657400c0300002000100001c20001004736563320561706e696303636f6d00c0300002000100001c2000070473656333c0bfc07b0001000100001c200004ca0c1d3bc07b001c000100001c20001020010dc02001000a4608000000000059c0ba0001000100001c200004ca0c1d3cc0d6001c000100001c20001020010dc0000100004777000000000140"
----------------------------------------------------------------

spec :: Spec
spec = do
    describe "decode" $ do
        it "decodes double pointers correctly" $ do
            let Right x1 = decode $ fromHexString test_doublePointer
                Right x2 = decode (encode x1)
                Right x3 = decode (encode x2)
            x3 `shouldBe` x2

----------------------------------------------------------------

fromHexString :: BL.ByteString -> BL.ByteString
fromHexString = BL.fromStrict . fromHexString' . BL.toStrict

fromHexString' :: ByteString -> ByteString
fromHexString' (PS fptr off len) = unsafeCreate size $ \dst ->
    withForeignPtr fptr $ \src -> go (src `plusPtr` off) dst 0
  where
    size = len `div` 2
    go from to bytes
      | bytes == size = return ()
      | otherwise    = do
          w1 <- peek from
          w2 <- peekByteOff from 1
          let w = hex2w (w1,w2)
          poke to w
          go (from `plusPtr` 2) (to `plusPtr` 1) (bytes + 1)

hex2w :: (Word8, Word8) -> Word8
hex2w (w1,w2) = h2w w1 * 16 + h2w w2

h2w :: Word8 -> Word8
h2w w
  | isDigit w = w - _0
  | otherwise = w - _a + 10
