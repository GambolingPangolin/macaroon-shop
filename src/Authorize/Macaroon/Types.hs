{-# LANGUAGE OverloadedStrings #-}

module Authorize.Macaroon.Types (
    MacaroonId (..),
    Macaroon (..),
    Caveat (..),
    SealedMacaroon (..),
    Key (..),
    KeyId (..),
    Signature (..),
    Location,
) where

import Authorize.Macaroon.Serialize qualified as MS
import Control.Monad (unless)
import Data.ByteArray (
    ByteArray,
    ByteArrayAccess,
    ScrubbedBytes,
 )
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Maybe (fromMaybe)
import Data.Serialize (Serialize (..))
import Data.Serialize qualified as S

type Location = ByteString

newtype MacaroonId = MacaroonId {unMacaroonId :: ByteString}
    deriving (Eq, Ord, Show, ByteArrayAccess, Serialize)

newtype Key = Key {unKey :: ScrubbedBytes} deriving (Eq, Ord, Show, ByteArrayAccess)

newtype KeyId = KeyId {unKeyId :: ByteString} deriving (Eq, Ord, Show, ByteArrayAccess)

newtype Signature = Signature {unSignature :: ByteString}
    deriving
        ( Eq
        , Ord
        , Semigroup
        , Monoid
        , ByteArray
        , ByteArrayAccess
        , Serialize
        , Show
        )

data Macaroon = Macaroon
    { locationHint :: Location
    , identifier :: MacaroonId
    , caveats :: [Caveat]
    , macaroonSignature :: Signature
    }
    deriving (Eq, Show)

instance Serialize Macaroon where
    put (Macaroon loc i cs sig) = do
        S.putWord8 2 -- version byte
        unless (BS.null loc) $ MS.putField MS.fieldLocation loc
        MS.putField MS.fieldIdentifier $ unMacaroonId i
        put MS.fieldEOS

        mapM_ put cs
        put MS.fieldEOS

        MS.putField MS.fieldSignature $ unSignature sig

    get = do
        getVersion

        mloc <- MS.getOptionalField MS.fieldLocation
        mid <- MacaroonId <$> MS.getField MS.fieldIdentifier
        MS.getEOS

        cs <- getCaveats
        MS.getEOS

        sig <- Signature <$> MS.getField MS.fieldSignature
        return $ Macaroon (fromMaybe mempty mloc) mid cs sig
      where
        getVersion = do
            v <- S.getWord8
            if v == 2 then return () else fail "Unsupported macaroon version"

        getCaveats = do
            eos <- MS.atEOS
            if eos then return [] else (:) <$> get <*> getCaveats

data Caveat = Caveat
    { caveatLocationHint :: Location
    -- ^ Note: The location hint is not authenticated
    , caveatKeyId :: Maybe KeyId
    -- ^ First party caveats do not require a key ident
    , caveatContent :: ByteString
    -- ^ content semantics are determined in the application layer
    }
    deriving (Eq, Show)

instance Serialize Caveat where
    put (Caveat loc mk c) = do
        unless (BS.null loc) $ MS.putField MS.fieldLocation loc
        MS.putField MS.fieldIdentifier c
        mapM_ (MS.putField MS.fieldVerificationId . unKeyId) mk
        put MS.fieldEOS

    get =
        makeCaveat
            <$> MS.getOptionalField MS.fieldLocation
            <*> MS.getField MS.fieldIdentifier
            <*> MS.getOptionalField MS.fieldVerificationId
            <* MS.getEOS
      where
        makeCaveat mloc c mkeyid = Caveat (fromMaybe mempty mloc) (KeyId <$> mkeyid) c

-- | Couple a macaroon with its discharges.  Application developers should
-- only produce these values either by invoking @prepareForRequest@ or by
-- deserializing a client token.
data SealedMacaroon = SealedMacaroon
    { rootMacaroon :: Macaroon
    , dischargeMacaroons :: [Macaroon]
    }
    deriving (Eq, Show)

instance Serialize SealedMacaroon where
    put (SealedMacaroon r ds) = put r >> mapM_ put ds
    get = SealedMacaroon <$> get <*> getMacaroons
      where
        getMacaroons = do
            n <- S.remaining
            if n > 0 then (:) <$> get <*> getMacaroons else return []
