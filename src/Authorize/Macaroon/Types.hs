{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}

module Authorize.Macaroon.Types
    ( MacaroonId (..)
    , Macaroon (..)
    , Caveat (..)

    , SealedMacaroon (..)

    , Key (..)
    , KeyId (..)
    , Signature (..)
    , Location
    ) where

import           Control.Monad                (unless)
import           Data.ByteArray               (ByteArray, ByteArrayAccess,
                                               ScrubbedBytes)
import           Data.ByteString              (ByteString)
import qualified Data.ByteString              as BS
import           Data.Maybe                   (fromMaybe)
import           Data.Serialize               (Serialize (..))
import qualified Data.Serialize               as S

import           Authorize.Macaroon.Serialize


type Location = ByteString


newtype MacaroonId = MacaroonId { unMacaroonId :: ByteString }
    deriving (Eq, Ord, Show, ByteArrayAccess, Serialize)


newtype Key = Key { unKey :: ScrubbedBytes } deriving (Eq, Ord, Show, ByteArrayAccess)


newtype KeyId = KeyId { unKeyId :: ByteString } deriving (Eq, Ord, Show, ByteArrayAccess)


newtype Signature = Signature { unSignature :: ByteString }
    deriving ( Eq
             , Ord
             , Semigroup
             , Monoid
             , ByteArray
             , ByteArrayAccess
             , Serialize
             , Show
             )


data Macaroon = Macaroon
    { locationHint      :: Location
    , identifier        :: MacaroonId
    , caveats           :: [Caveat]
    , macaroonSignature :: Signature
    } deriving (Eq, Show)


instance Serialize Macaroon where
    put (Macaroon loc i cs sig) = do
        S.putWord8 2 -- version byte

        unless (BS.null loc) $ putField fieldLocation loc
        putField fieldIdentifier $ unMacaroonId i
        put fieldEOS

        mapM_ put cs
        put fieldEOS

        putField fieldSignature $ unSignature sig

    get = do
        getVersion

        mloc <- getOptionalField fieldLocation
        mid  <- MacaroonId <$> getField fieldIdentifier
        getEOS

        cs <- getCaveats
        getEOS

        sig <- Signature <$> getField fieldSignature
        return $ Macaroon (fromMaybe mempty mloc) mid cs sig

        where
        getVersion = do
            v <- S.getWord8
            if v == 2 then return () else fail "Unsupported macaroon version"

        getCaveats = do
            eos <- atEOS
            if eos then return [] else (:) <$> get <*> getCaveats


data Caveat = Caveat
    { caveatLocationHint :: Location
    -- ^ Note: The location hint is not authenticated
    , caveatKeyId        :: Maybe KeyId
    -- ^ First party caveats do not require a key ident
    , caveatContent      :: ByteString
    -- ^ content semantics are determined in the application layer
    } deriving (Eq, Show)


instance Serialize Caveat where
    put (Caveat loc mk c) = do
        unless (BS.null loc) $ putField fieldLocation loc
        putField fieldIdentifier c
        mapM_ (putField fieldVerificationId . unKeyId) mk
        put fieldEOS

    get = makeCaveat
            <$> getOptionalField fieldLocation
            <*> getField fieldIdentifier
            <*> getOptionalField fieldVerificationId
          <* getEOS
        where
        makeCaveat mloc c mkeyid = Caveat (fromMaybe mempty mloc) (KeyId <$> mkeyid) c


-- | Couple a macaroon with its discharges.  Application developers should
-- only produce these values either by invoking @prepareForRequest@ or by
-- deserializing a client token.
data SealedMacaroon = SealedMacaroon
    { rootMacaroon       :: Macaroon
    , dischargeMacaroons :: [Macaroon]
    } deriving (Eq, Show)


instance Serialize SealedMacaroon where
    put (SealedMacaroon r ds) = put r >> mapM_ put ds
    get = SealedMacaroon <$> get <*> getMacaroons
        where
        getMacaroons = do
            n <- S.remaining
            if n > 0 then (:) <$> get <*> getMacaroons else return []
