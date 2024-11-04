{-# LANGUAGE OverloadedStrings #-}

module ECDHChat where

import Crypto.Error (CryptoFailable(..))
import Crypto.Number.Serialize (os2ip, ip2os)
import Crypto.PubKey.ECC (Curve, getCurveByName, generateKeyPair, Point(..))
import Crypto.PubKey.ECC.Types (getPointX, getPointY)
import Crypto.Hash (hashWith, SHA256)
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (BlockCipher(..), Cipher(..), IV, makeIV, nullIV)
import Crypto.Cipher.AES.GCM (encryptGCM, decryptGCM, AuthTag)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.ByteString.Char8 (pack, unpack)
import Data.ByteString.Base64 (encode, decode)
import Network.Socket
import System.IO

curve :: Curve
curve = getCurveByName "secp256k1"

generateKeyPair' :: IO (Point, Point)
generateKeyPair' = generateKeyPair curve

serializePoint :: Point -> ByteString
serializePoint (Point x y) = ip2os x <> ip2os y
serializePoint PointO = error "Point at infinity"

deserializePoint :: ByteString -> Maybe Point
deserializePoint bytes = case splitAt (BS.length bytes `div` 2) bytes of
    (xBytes, yBytes) -> Just (Point (os2ip xBytes) (os2ip yBytes))

ecdh :: Point -> Point -> Maybe ByteString
ecdh publicKey privateKey =
    let sharedSecret = multiply curve privateKey publicKey
    in serializePoint sharedSecret

hash :: ByteString -> ByteString
hash = convert . hashWith SHA256

deriveKey :: ByteString -> ByteString
deriveKey = hash

encryptGCM :: ByteString -> ByteString -> ByteString -> (ByteString, AuthTag)
encryptGCM key iv plaintext =
  case cipherInit key of
    CryptoPassed cipher ->
      let Just iv' = makeIV iv
          (ciphertext, authTag) = encryptGCM cipher iv' mempty plaintext
      in (ciphertext, authTag)
    CryptoFailed e -> error (show e)

decryptGCM :: ByteString -> ByteString -> ByteString -> AuthTag -> Either String ByteString
decryptGCM key iv ciphertext authTag =
  case cipherInit key of
    CryptoPassed cipher ->
      let Just iv' = makeIV iv
      in decryptGCM cipher iv' mempty ciphertext authTag
    CryptoFailed e -> Left (show e)

sendSecure :: Socket -> ByteString -> ByteString -> IO ()
sendSecure sock key plaintext = do
  let (ciphertext, authTag) = encryptGCM key nullIV plaintext
  send sock (encode ciphertext)
  send sock (encode authTag)

receiveSecure :: Socket -> ByteString -> IO (Either String ByteString)
receiveSecure sock key = do
  ciphertext <- recv sock 1024
  authTag <- recv sock 1024
  case (decode ciphertext, decode authTag) of
    (Right ct, Right at) -> decryptGCM key nullIV ct at
    _ -> return $ Left "Error in decoding message or authentication tag."

handleConnection :: Socket -> ByteString -> IO ()
handleConnection sock sharedKey = do
  putStrLn "Enter message to send:"
  message <- getLine
  sendSecure sock sharedKey (pack message)
  putStrLn "Message sent. Waiting for response..."
  response <- receiveSecure sock sharedKey
  case response of
    Right msg -> putStrLn $ "Received message: " ++ unpack msg
    Left err -> putStrLn $ "Error receiving message: " ++ err

startServer :: IO ()
startServer = do
  sock <- socket AF_INET Stream 0
  bind sock (SockAddrInet 8080 iNADDR_ANY)
  listen sock 1
  putStrLn "Server listening on port 8080."
  (conn, _) <- accept sock
  putStrLn "Client connected."
  (privateKey, publicKey) <- generateKeyPair'
  send conn (serializePoint publicKey)
  clientPublicKeyBytes <- recv conn 1024
  case deserializePoint clientPublicKeyBytes of
    Just clientPublicKey -> do
      let sharedSecret = ecdh clientPublicKey privateKey
      case sharedSecret of
        Just secret -> handleConnection conn (deriveKey secret)
        Nothing -> putStrLn "Error in ECDH key exchange."
    Nothing -> putStrLn "Invalid client public key received."
  close conn

startClient :: IO ()
startClient = do
  sock <- socket AF_INET Stream 0
  connect sock (SockAddrInet 8080 iNADDR_ANY)
  putStrLn "Connected to server."
  serverPublicKeyBytes <- recv sock 1024
  case deserializePoint serverPublicKeyBytes of
    Just serverPublicKey -> do
      (privateKey, publicKey) <- generateKeyPair'
      send sock (serializePoint publicKey)
      let sharedSecret = ecdh serverPublicKey privateKey
      case sharedSecret of
        Just secret -> handleConnection sock (deriveKey secret)
        Nothing -> putStrLn "Error in ECDH key exchange."
    Nothing -> putStrLn "Invalid server public key received."
  close sock

main :: IO ()
main = do
  putStrLn "Do you want to start as a server or client?"
  response <- getLine
  case response of
    "server" -> startServer
    "client" -> startClient
    _ -> putStrLn "Invalid input. Enter 'server' or 'client'."
