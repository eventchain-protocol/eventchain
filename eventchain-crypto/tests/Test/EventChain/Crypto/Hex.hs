-- | Hex, for reading published vectors as their documents print them.
module Test.EventChain.Crypto.Hex
    ( hex
    , unhex
    ) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as C8
import Data.Char (digitToInt, isHexDigit)
import Numeric (showHex)

-- | Lowercase hex, as the vectors below are written.
hex :: ByteString -> ByteString
hex = C8.pack . concatMap byte . BS.unpack
  where
    byte w = case showHex w "" of
        [c] -> ['0', c]
        s -> s

-- | Read a vector as printed. Errors loudly: a malformed vector is a broken test, not a finding.
unhex :: ByteString -> ByteString
unhex t
    | odd (C8.length t) = error ("unhex: odd length in " <> show t)
    | not (C8.all isHexDigit t) = error ("unhex: not hex: " <> show t)
    | otherwise = BS.pack (go (C8.unpack t))
  where
    go (a : b : r) = fromIntegral (digitToInt a * 16 + digitToInt b) : go r
    go _ = []
