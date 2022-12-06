module Authorize.Macaroon.Serialize (
    fieldEOS,
    fieldLocation,
    fieldIdentifier,
    fieldVerificationId,
    fieldSignature,
    putField,
    getField,
    getOptionalField,
    getEOS,
    atEOS,
) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Bytes.Serial qualified as By
import Data.Bytes.VarInt (VarInt (..))
import Data.Serialize (Get, Put, Serialize (..))
import Data.Serialize qualified as S
import Data.Word (Word8)

fieldEOS :: Word8
fieldEOS = 0

fieldLocation :: Word8
fieldLocation = 1

fieldIdentifier :: Word8
fieldIdentifier = 2

fieldVerificationId :: Word8
fieldVerificationId = 4

fieldSignature :: Word8
fieldSignature = 6

putField :: Word8 -> ByteString -> Put
putField fieldId dat =
    put fieldId >> By.serialize (VarInt $ BS.length dat) >> S.putByteString dat

getOptionalField :: Word8 -> Get (Maybe ByteString)
getOptionalField f = do
    n <- S.lookAhead S.getWord8
    if n == f
        then S.getWord8 >> Just <$> getFieldData
        else return Nothing

getField :: Word8 -> Get ByteString
getField f = do
    n <- S.getWord8
    if n == f then getFieldData else fail $ "Expecting field " <> show f <> " but got " <> show n

getFieldData :: Get ByteString
getFieldData = do
    VarInt n <- By.deserialize
    S.getBytes n

getEOS :: Get ()
getEOS = do
    f <- S.getWord8
    if f == fieldEOS then return () else fail "Expecting EOS"

atEOS :: Get Bool
atEOS = (== fieldEOS) <$> S.lookAhead S.getWord8
