{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

module Main (main) where

import Authorize.Macaroon (
    Macaroon,
    SealedMacaroon (..),
    VerificationFailure (..),
    addThirdPartyCaveat,
    createDischargeMacaroon,
    sealMacaroon,
    verify,
 )
import Authorize.Macaroon.Gen qualified as G
import Control.Monad (foldM)
import Control.Monad.IO.Class (liftIO)
import Data.Serialize (Serialize)
import Data.Serialize qualified as S
import Data.Set qualified as Set
import Hedgehog (
    Gen,
    Group (..),
    Property,
    PropertyT,
    TestLimit,
    assert,
    checkParallel,
    diff,
    forAll,
    property,
    withTests,
    (===),
 )
import Hedgehog.Gen qualified as Gen
import Hedgehog.Main (defaultMain)
import Hedgehog.Range qualified as Range

main :: IO ()
main =
    defaultMain
        [ checkParallel testSerialization
        , checkParallel testVerification
        ]

testSerialization :: Group
testSerialization =
    Group
        "Serialization"
        [ ("Macaroon", testMacaroonSerialization)
        , ("SealedMacaroon", testSealedMacaroonSerialization)
        ]

testMacaroonSerialization :: Property
testMacaroonSerialization = roundTripProperty 500 G.macaroon

testSealedMacaroonSerialization :: Property
testSealedMacaroonSerialization = roundTripProperty 20 G.sealedMacaroon

roundTripProperty :: (Eq a, Show a, Serialize a) => TestLimit -> Gen a -> Property
roundTripProperty n g = withTests n . property $ do
    x <- forAll g
    diff (roundTrip x) (==) (Right x)

roundTrip :: Serialize a => a -> Either String a
roundTrip = S.decode . S.encode

testVerification :: Group
testVerification =
    Group
        "Verification"
        [ ("Passes (simple)", testPasses)
        , ("Passes (complex)", testComplexPasses)
        , ("Fails (missing discharge)", testMissingDischarge)
        , ("Fails (invalid key)", testInvalidKey)
        , ("Fails (invalid binding)", testInvalidBinding)
        ]

testPasses :: Property
testPasses = withTests 100 . property $ do
    (k, m, cs) <- forAll G.validMacaroon
    verify k (SealedMacaroon m []) === Right cs

testComplexPasses :: Property
testComplexPasses = withTests 100 . property $ do
    (k, m, cs) <- forAll G.validMacaroon
    sm <- uncurry sealMacaroon <$> addThirdPartyCaveats m
    verify k sm === Right cs

addThirdPartyCaveats :: Macaroon -> PropertyT IO (Macaroon, [Macaroon])
addThirdPartyCaveats m0 =
    forAll genThirdPartyCaveats >>= foldM step (m0, [])
  where
    genThirdPartyCaveats =
        Gen.set (Range.constant 1 10) G.content >>= traverse inflateTPData . Set.toList
    inflateTPData c = (,,c) <$> G.key <*> G.location

    step (m, ds) (ck, l, c) = do
        m' <- liftIO $ addThirdPartyCaveat m ck l c
        let d = createDischargeMacaroon ck l c []
        return (m', ds <> [d])

testMissingDischarge :: Property
testMissingDischarge = withTests 100 . property $ do
    (k, m, _) <- forAll G.validMacaroon
    (m', _) <- addThirdPartyCaveats m
    assert . isMissingDischarge $ verify k (SealedMacaroon m' [])
  where
    isMissingDischarge (Left (MissingDischargeMacaroon _)) = True
    isMissingDischarge _ = False

testInvalidKey :: Property
testInvalidKey = withTests 100 . property $ do
    k <- forAll G.key
    (_, m, _) <- forAll G.validMacaroon
    assert . isInvalidSignature $ verify k (SealedMacaroon m [])
  where
    isInvalidSignature (Left (InvalidSignature _)) = True
    isInvalidSignature _ = False

testInvalidBinding :: Property
testInvalidBinding = withTests 100 . property $ do
    (k, m, _) <- forAll G.validMacaroon
    sm <- uncurry SealedMacaroon <$> addThirdPartyCaveats m
    assert . isInvalidBinding $ verify k sm
  where
    isInvalidBinding (Left (InvalidBinding _)) = True
    isInvalidBinding _ = False
