{-# LANGUAGE OverloadedStrings #-}

module ECDH where

import Crypto.Error (CryptoFailable)
import Crypto.Number.Serialize (os2ip, ip2os)
import Crypto.PubKey.ECC (Curve, getCurveByName, generateKeyPair)
import Crypto.PubKey.ECC.Types (Point, getPointX, getPointY)
import Data.ByteArray (ByteArrayAccess, convert)
import Data.ByteString (ByteString)

-- | Curve parameters
curve :: Curve
curve = getCurveByName "secp256k1"

-- | Generate a key pair
generateKeyPair' :: IO (Point, Point)
generateKeyPair' = generateKeyPair curve

-- | Serialize a point to a ByteString
serializePoint :: Point -> ByteString
serializePoint point = os2ip $ getPointX point ++ getPointY point

-- | Deserialize a ByteString to a point
deserializePoint :: ByteString -> Point
deserializePoint bytes = let (x, y) = ip2os bytes in point x y

-- | ECDH key exchange
ecdh :: Point -> Point -> IO ByteString
ecdh publicKey privateKey = do
  let sharedSecret = multiply curve privateKey publicKey
  return $ serializePoint sharedSecret

-- | Multiply a point by a scalar
multiply :: Curve -> Point -> Point -> Point
multiply curve scalar point = ...
  -- implementation omitted for brevity

-- | Example usage
main :: IO ()
main = do
  (user-1PrivateKey, user-1PublicKey) <- generateKeyPair'
  (user-2PrivateKey, user-2PublicKey) <- generateKeyPair'

  let user-1SharedSecret = ecdh user-2PublicKey user-1PrivateKey
  let user-2SharedSecret = ecdh user-1PublicKey user-2PrivateKey

  print $ "user-1 shared secret: " ++ show user-1SharedSecret
  print $ "user-2 shared secret: " ++ show user-2SharedSecret
