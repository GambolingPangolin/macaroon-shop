-- |
-- Module:      Authorize.Macaroon
-- License:     ISC
-- Maintainer:  ics@gambolingpangolin.com
-- Stability:   experimental
--
-- This module contains an implementation of macaroons as described in
-- <http://theory.stanford.edu/~ataly/Papers/macaroons.pdf>.  The
-- serialization, cryptography, and validation semantics are compatible with
-- go-macaroons <https://github.com/go-macaroon/macaroon>.
module Authorize.Macaroon
    (
    -- * Types

      MacaroonId (..)
    , Macaroon
    , SealedMacaroon (..)

    , Key (..)
    , Location

    -- * Core interface

    , createMacaroon
    , addFirstPartyCaveat
    , addThirdPartyCaveat
    , extractThirdPartyCaveats
    , sealMacaroon

    , createDischargeMacaroon

    , verify
    , VerificationFailure (..)
    ) where

import           Data.ByteString           (ByteString)
import           Data.List                 (foldl')
import           Data.Maybe                (isJust)

import           Authorize.Macaroon.Crypto
import           Authorize.Macaroon.Types
import           Authorize.Macaroon.Verify


-- | Mint a macaroon
createMacaroon
    :: Key
    -- ^ signing key
    -> MacaroonId
    -- ^ identifier for this macaroon
    -> Location
    -- ^ location hint
    -> [ByteString]
    -- ^ first party caveats to include
    -> Macaroon
createMacaroon k mid loc = foldl' addFirstPartyCaveat m0
    where
    m0 = Macaroon loc mid [] $ createSignature (deriveKey k) mid


-- | A first party caveat corresponds to a proposition that might or might not
-- hold in the validation context of the macaroon.
addFirstPartyCaveat :: Macaroon -> ByteString -> Macaroon
addFirstPartyCaveat m = addCaveat m . Caveat mempty Nothing


-- | A third party caveat links the macaroon to an additional key, and must be
-- discharged by a supplementary macaroon in order to validate.
addThirdPartyCaveat
    :: Macaroon
    -> Key
    -- ^ third party key
    -> Location
    -> ByteString
    -> IO Macaroon
addThirdPartyCaveat m ck loc c
    = addC <$> encryptKey (macaroonSignature m) (deriveKey ck)
    where
    addC k = addCaveat m $ Caveat loc (Just k) c


addCaveat :: Macaroon -> Caveat -> Macaroon
addCaveat m c@Caveat{ caveatKeyId = k, caveatContent = cc }
    = m { caveats           = caveats m <> [c]
        , macaroonSignature = updateSignature (macaroonSignature m) k cc
        }


-- | Get the third party caveats encoded in the macaroon
extractThirdPartyCaveats :: Macaroon -> [ByteString]
extractThirdPartyCaveats = fmap caveatContent . filter isThirdParty . caveats


isThirdParty :: Caveat -> Bool
isThirdParty = isJust . caveatKeyId


-- | Mint a macaroon discharging a third party caveat
createDischargeMacaroon
    :: Key
    -- ^ discharge key
    -> Location
    -- ^ location hint
    -> ByteString
    -- ^ caveat to discharge
    -> [ByteString]
    -- ^ additional first party caveats to include
    -> Macaroon
createDischargeMacaroon k l c = createMacaroon k (MacaroonId c) l


-- | In order to secure discharge macaroons, they must be bound to the root macaroon before transmission.
sealMacaroon
    :: Macaroon
    -- ^ root macaroon
    -> [Macaroon]
    -- ^ discharge macaroons
    -> SealedMacaroon
sealMacaroon m@Macaroon{ macaroonSignature = s } ms
    = SealedMacaroon m $ bindMacaroon <$> ms
    where
    bindMacaroon m'@Macaroon{ macaroonSignature = s' }
        = m' { macaroonSignature = bindForRequest s s' }
