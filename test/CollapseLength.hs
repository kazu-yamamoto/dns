{-# LANGUAGE RecordWildCards #-}

module CollapseLength where

import Data.Function (on)
import Network.DNS
import Test.Hspec (Expectation, shouldBe)

class CollapseLength a where
  -- | Sets 'rrlength' fields to 0.
  collapseLength :: a -> a

instance CollapseLength b => CollapseLength (Either a b) where
  collapseLength = fmap collapseLength

instance CollapseLength DNSMessage where
  collapseLength DNSMessage{..} = DNSMessage
    { answer = map collapseLength answer
    , authority = map collapseLength authority
    , additional = map collapseLength additional
    , .. }

instance CollapseLength ResourceRecord where
  collapseLength ResourceRecord{..} = ResourceRecord
    { rrlength = 0
    , .. }

-- | Applies 'collapseLength' before comparison,
-- which is useful in tests that compare a synthesized
-- DNS message or resource record with a decoded one.
--
-- Of course, do not collapse the length if your test
-- is intended to check whether the length field in an
-- encoded resource record header has a particular value.
shouldBeCL :: (CollapseLength a, Eq a, Show a) => a -> a -> Expectation
shouldBeCL = shouldBe `on` collapseLength
infix 1 `shouldBeCL`
