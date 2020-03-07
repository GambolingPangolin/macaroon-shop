module Authorize.Macaroon.Gen
    ( sealedMacaroon
    , macaroon
    , location
    , caveat
    , content
    , key
    , signature
    , validMacaroon
    ) where

import           Data.ByteArray           (convert)
import           Data.ByteString          (ByteString)
import           Data.Set                 (Set)
import qualified Data.Set                 as Set
import           Hedgehog                 (Gen)
import qualified Hedgehog.Gen             as Gen
import qualified Hedgehog.Range           as Range

import           Authorize.Macaroon
import           Authorize.Macaroon.Types (Caveat (..), KeyId (..),
                                           Macaroon (..), Signature (..))


sealedMacaroon :: Gen SealedMacaroon
sealedMacaroon = SealedMacaroon <$> macaroon <*> macaroons
    where
    macaroons = Gen.list (Range.constant 0 100) macaroon


macaroon :: Gen Macaroon
macaroon = Macaroon <$> location <*> genIdentifier <*> genCaveats <*> signature
    where
    genCaveats = Gen.list (Range.constant 0 100) caveat


caveat :: Gen Caveat
caveat = Caveat <$> location <*> gKeyId <*> content
    where
    gKeyId = Gen.choice [pure Nothing, Just <$> keyId]


content :: Gen ByteString
content = Gen.bytes $ Range.constant 1 128


keyId :: Gen KeyId
keyId = KeyId <$> Gen.bytes (Range.singleton 32)


location :: Gen Location
location = Gen.bytes $ Range.constant 0 64


genIdentifier :: Gen MacaroonId
genIdentifier = MacaroonId <$> Gen.bytes (Range.constant 1 256)


signature :: Gen Signature
signature = Signature <$> Gen.bytes (Range.singleton 32)


validMacaroon :: Gen (Key, Macaroon, Set ByteString)
validMacaroon = do
    k   <- key
    i   <- genIdentifier
    cs  <- Gen.list (Range.constant 1 10) content
    loc <- location
    let m = createMacaroon k i loc cs
    return (k, m, Set.fromList cs)


key :: Gen Key
key = Key . convert <$> Gen.bytes (Range.singleton 32)
