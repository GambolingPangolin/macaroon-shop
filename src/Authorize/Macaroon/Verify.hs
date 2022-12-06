module Authorize.Macaroon.Verify (
    VerificationFailure (..),
    verify,
    recalcSignature,
) where

import Control.Arrow ((&&&))
import Control.Monad (foldM, unless)
import Data.ByteArray (constEq)
import Data.ByteString (ByteString)
import Data.Foldable (foldl')
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Set (Set)
import qualified Data.Set as Set

import Authorize.Macaroon.Crypto
import Authorize.Macaroon.Types

data VerificationFailure
    = InvalidSignature MacaroonId
    | InvalidBinding MacaroonId
    | MissingDischargeMacaroon MacaroonId
    | ExcessDischarges [Macaroon]
    | ThirdPartyKeyError MacaroonId
    deriving (Eq, Show)

type Discharges = Map MacaroonId Macaroon

-- | Macaroon verification succeeds by producing a set of first party caveats
-- requiring further validation.
verify ::
    -- | root key
    Key ->
    SealedMacaroon ->
    Either VerificationFailure (Set ByteString)
verify rootKey (SealedMacaroon m ms) = do
    (cs, ds') <- verify' (deriveKey rootKey) m ds
    unless (Map.null ds') $ Left (ExcessDischarges $ Map.elems ds')
    return cs
  where
    ds = Map.fromList $ (identifier &&& id) <$> ms

verify' ::
    Key ->
    Macaroon ->
    Discharges ->
    Either VerificationFailure (Set ByteString, Discharges)
verify' k m ds = checkSig =<< foldM step (sig0, mempty, ds) (caveats m)
  where
    step (sig, cs, ds') (Caveat _ mk c) =
        updateSig mk c sig <$> maybe firstP (verThirdP sig) mk c cs ds'

    firstP c cs ds' = return (Set.singleton c <> cs, ds')
    verThirdP = verifyThirdParty (macaroonSignature m)

    sig0 = createSignature k (identifier m)
    updateSig mk c sig (x, y) = (updateSignature sig mk c, x, y)

    checkSig (sig, cs', ds') =
        (cs', ds')
            <$ unless
                (sig `constEq` macaroonSignature m)
                (Left . InvalidSignature $ identifier m)

verifyThirdParty ::
    -- | root signature
    Signature ->
    -- | running signature
    Signature ->
    KeyId ->
    ByteString ->
    Set ByteString ->
    Discharges ->
    Either VerificationFailure (Set ByteString, Discharges)
verifyThirdParty rootSig runningSig k c acc ds = do
    (m, ds') <- getDischarge (MacaroonId c) ds
    k' <- getKey (identifier m) runningSig k

    let unboundSig = recalcSignature k' (identifier m) (caveats m)
        dischargeSig = macaroonSignature m
        unboundDischarge = m{macaroonSignature = unboundSig}

    unless (bindForRequest rootSig unboundSig == dischargeSig) $
        Left (InvalidBinding $ identifier m)

    (acc', ds'') <- verify' k' unboundDischarge ds'
    return (acc' <> acc, ds'')

getDischarge ::
    MacaroonId ->
    Discharges ->
    Either VerificationFailure (Macaroon, Discharges)
getDischarge mid ds = maybe noDischarge someDischarge $ Map.lookup mid ds
  where
    someDischarge m = return (m, Map.delete mid ds)
    noDischarge = Left $ MissingDischargeMacaroon mid

getKey :: MacaroonId -> Signature -> KeyId -> Either VerificationFailure Key
getKey mid sig = maybe noKey return . decryptKey sig
  where
    noKey = Left $ ThirdPartyKeyError mid

recalcSignature :: Key -> MacaroonId -> [Caveat] -> Signature
recalcSignature k i = foldl' step (createSignature k i)
  where
    step sig (Caveat _ mk c) = updateSignature sig mk c
