{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections     #-}

module Main where

import           Control.Monad             (foldM)
import           Control.Monad.IO.Class    (liftIO)
import           Data.Serialize            (Serialize)
import qualified Data.Serialize            as S
import qualified Data.Set                  as Set
import           Hedgehog                  (Gen, Group (..), Property,
                                            TestLimit, checkParallel, diff,
                                            forAll, property, withTests, (===))
import           Hedgehog.Main             (defaultMain)
import qualified Hedgehog.Range            as Range

import           Authorize.Macaroon        (MacaroonGroup (..),
                                            addThirdPartyCaveat,
                                            createDischargeMacaroon,
                                            prepareForRequest, verify)
import           Authorize.Macaroon.Crypto (decryptKey, encryptKey)
import qualified Authorize.Macaroon.Gen    as G
import qualified Hedgehog.Gen              as Gen


main :: IO ()
main = defaultMain [ checkParallel testSerialization
                   , checkParallel testCrypto
                   , checkParallel testValidation
                   ]


testSerialization :: Group
testSerialization = Group "Serialization"
    [ ("Caveat", testCaveatSerialization)
    , ("Macaroon", testMacaroonSerialization)
    , ("MacaroonGroup", testMacaroonGroupSerialization)
    ]


testCaveatSerialization :: Property
testCaveatSerialization = roundTripProperty 1000 G.caveat


testMacaroonSerialization :: Property
testMacaroonSerialization = roundTripProperty 500 G.macaroon


testMacaroonGroupSerialization :: Property
testMacaroonGroupSerialization = roundTripProperty 20 G.macaroonGroup


roundTripProperty :: (Eq a, Show a, Serialize a) => TestLimit -> Gen a -> Property
roundTripProperty n g = withTests n . property $ do
    x <- forAll g
    diff (roundTrip x) (==) (Right x)


roundTrip :: Serialize a => a -> Either String a
roundTrip = S.decode . S.encode


testCrypto :: Group
testCrypto = Group "Cryptography"
    [ ("Key encryption", testKeyEncryption) ]


testKeyEncryption :: Property
testKeyEncryption = withTests 10 . property $ do
    x  <- forAll G.key
    s  <- forAll G.signature
    ct <- liftIO $ encryptKey s x
    decryptKey s ct === Just x


testValidation :: Group
testValidation = Group "Validation"
    [ ("Passes (simple)", testPasses)
    , ("Passes (complex)", testComplexPasses)
    ]


testPasses :: Property
testPasses = withTests 100 . property $ do
    (k, m, cs) <- forAll G.validMacaroon
    verify k (MacaroonGroup m []) === Right cs


testComplexPasses :: Property
testComplexPasses = withTests 100 . property $ do
    (k, m, cs) <- forAll G.validMacaroon
    mg <- fmap (uncurry prepareForRequest) . foldM step (m, []) =<< forAll genTPData
    verify k mg === Right cs

    where
    tpCaveats       = Gen.set (Range.constant 1 10) G.content
    genTPData       = tpCaveats >>= traverse inflateTPData . Set.toList
    inflateTPData c = (, , c) <$> G.key <*> G.location

    step (m, ds) (ck, l, c) = do
        m' <- liftIO $ addThirdPartyCaveat m ck l c
        let d = createDischargeMacaroon ck l c []
        return (m', ds <> [d])
