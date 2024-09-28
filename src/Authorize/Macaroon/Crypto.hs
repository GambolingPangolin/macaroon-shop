{-# LANGUAGE OverloadedStrings #-}

module Authorize.Macaroon.Crypto (
    createSignature,
    updateSignature,
    encryptKey,
    decryptKey,
    bindForRequest,
    deriveKey,
) where

import Authorize.Macaroon.Types (
    Key (..),
    KeyId (..),
    MacaroonId (..),
    Signature (..),
 )
import Crypto.Hash (SHA256)
import Crypto.MAC.HMAC (HMAC, hmac)
import Crypto.Saltine.Class qualified as Nacl
import Crypto.Saltine.Core.SecretBox (
    newNonce,
    secretbox,
    secretboxOpen,
 )
import Crypto.Saltine.Internal.SecretBox (secretbox_noncebytes)
import Data.ByteArray (
    ByteArray,
    ByteArrayAccess,
    convert,
 )
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS

createSignature :: Key -> MacaroonId -> Signature
createSignature k m = Signature $ keyedHash k m

updateSignature :: Signature -> Maybe KeyId -> ByteString -> Signature
updateSignature s kid c = Signature $ maybe (keyedHash s) (keyedPairHash s) kid c

encryptKey :: Signature -> Key -> IO KeyId
encryptKey (Signature s) (Key k) = do
    n <- newNonce
    key <- maybe err return $ Nacl.decode s
    return . KeyId $ Nacl.encode n <> secretbox key n (convert k)
  where
    err = error "Unable to decode key"

decryptKey :: Signature -> KeyId -> Maybe Key
decryptKey (Signature s) (KeyId kid) = do
    n <- Nacl.decode nonceBytes
    key <- Nacl.decode s
    Key . convert <$> secretboxOpen key n ct
  where
    (nonceBytes, ct) = BS.splitAt secretbox_noncebytes kid

bindForRequest :: Signature -> Signature -> Signature
bindForRequest = keyedPairHash zeroKey
  where
    zeroKey = BS.replicate 32 0x0

hmac256 :: (ByteArrayAccess k, ByteArrayAccess x) => k -> x -> HMAC SHA256
hmac256 = hmac

deriveKey :: Key -> Key
deriveKey (Key k) = Key . convert $ hmac256 tag k
  where
    tag :: ByteString
    tag = "macaroons-key-generator"

keyedHash ::
    (ByteArrayAccess k, ByteArrayAccess b, ByteArray c) =>
    k ->
    b ->
    c
keyedHash k = convert . hmac256 k

keyedPairHash ::
    ( ByteArrayAccess k
    , ByteArrayAccess b
    , ByteArrayAccess c
    , ByteArray d
    , Monoid d
    ) =>
    k ->
    b ->
    c ->
    d
keyedPairHash k x y =
    keyedHash k (keyedHash k x <> keyedHash k y :: ByteString)
