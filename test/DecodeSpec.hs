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

test_txt :: BL.ByteString
test_txt = "463181800001000100000000076e69636f6c6173046b766462076e647072696d6102696f0000100001c00c0010000100000e10000c6e69636f6c61732e6b766462"

test_dname :: BL.ByteString
test_dname = "b3c0818000010005000200010377777706376b616e616c02636f02696c0000010001c0100027000100000003000c0769737261656c3702727500c00c0005000100000003000603777777c02ec046000500010000255b0002c02ec02e000100010000003d000451daf938c02e000100010000003d0004c33ce84ac02e000200010005412b000c036e7332026137036f726700c02e000200010005412b0006036e7331c08a0000291000000000000000"

----------------------------------------------------------------

spec :: Spec
spec = do
    describe "decode" $ do
        it "decodes double pointers correctly" $ do
            let Right x1 = decode $ fromHexString test_doublePointer
                Right x2 = decode (encode x1)
                Right x3 = decode (encode x2)
            x3 `shouldBe` x2
        it "decodes dname" $ do
            let Right x1 = decode $ fromHexString test_dname
                Right x2 = decode (encode x1)
                Right x3 = decode (encode x2)
            print x1
            x3 `shouldBe` x2
        it "decodes txt" $ do
            let Right x1 = decode $ fromHexString test_txt
                Right x2 = decode (encode x1)
                Right x3 = decode (encode x2)
            print x1
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
