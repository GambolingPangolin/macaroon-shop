module Authorize.Macaroon.Gen (
    location,
    content,
    key,
    validMacaroon,
    macaroon,
    sealedMacaroon,
) where

import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.Set (Set)
import qualified Data.Set as Set
import Hedgehog (Gen)
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

import Authorize.Macaroon (
    Key (..),
    Location,
    Macaroon,
    MacaroonId (..),
    SealedMacaroon,
    createMacaroon,
    sealMacaroon,
 )

content :: Gen ByteString
content = Gen.bytes $ Range.constant 1 128

location :: Gen Location
location = Gen.bytes $ Range.constant 0 64

genIdentifier :: Gen MacaroonId
genIdentifier = MacaroonId <$> Gen.bytes (Range.constant 1 256)

sealedMacaroon :: Gen SealedMacaroon
sealedMacaroon = sealMacaroon <$> macaroon <*> macaroons
  where
    macaroons = Gen.list (Range.constant 1 10) macaroon

macaroon :: Gen Macaroon
macaroon = pr2 <$> validMacaroon
  where
    pr2 (_, x, _) = x

validMacaroon :: Gen (Key, Macaroon, Set ByteString)
validMacaroon = do
    k <- key
    i <- genIdentifier
    cs <- Gen.list (Range.constant 1 10) content
    loc <- location
    let m = createMacaroon k i loc cs
    return (k, m, Set.fromList cs)

key :: Gen Key
key = Key . convert <$> Gen.bytes (Range.singleton 32)
