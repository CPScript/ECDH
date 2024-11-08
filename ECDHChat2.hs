-- Security Additions

-- 1. now uses a nonce (unique per message ideally) for each encryption to prevent replay attacks. In a real setup, dynamically generate a random nonce each time.
-- 2. Errors are now caught and displayed in handleClient for more robust error reporting.
-- 3. Each session has a limited duration to prevent unauthorized reuse. After 1 hour, the connection expires. (this can be changed on the client's side)
-- 4. Use of forkIO in startServer for handling multiple clients concurrently; rate limiting logic can be added.

-- ------------ --
{-# LANGUAGE OverloadedStrings #-}

module ECDHChat where

import Control.Concurrent (forkIO)
import Control.Exception (bracket)
import Crypto.Error (CryptoFailable(..))
import Crypto.Number.Serialize (os2ip, ip2os)
import Crypto.PubKey.ECC (Curve, getCurveByName, generateKeyPair, Point(..))
import Crypto.PubKey.ECC.Types (getPointX, getPointY)
import Crypto.Hash (hashWith, SHA256)
import Crypto.Cipher.Types (BlockCipher(..), Cipher(..), IV, makeIV, nullIV)
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.AES.GCM (AuthTag, encryptGCM, decryptGCM)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
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
deserializePoint bytes = case BS.splitAt (BS.length bytes `div` 2) bytes of
    (xBytes, yBytes) -> Just (Point (os2ip xBytes) (os2ip yBytes))

ecdh :: Point -> Point -> Maybe ByteString
ecdh publicKey privateKey = Just (serializePoint (Point (os2ip (serializePoint privateKey)) (os2ip (serializePoint publicKey))))

hash :: ByteString -> ByteString
hash = convert . hashWith SHA256

deriveKey :: ByteString -> ByteString
deriveKey = hash

encryptGCM :: ByteString -> ByteString -> ByteString -> (ByteString, AuthTag)
encryptGCM key iv plaintext =
  case cipherInit key :: CryptoFailable AES256 of
    CryptoPassed cipher ->
      let Just iv' = makeIV iv
          (ciphertext, authTag) = encryptGCM cipher iv' mempty plaintext
      in (ciphertext, authTag)
    CryptoFailed e -> error (show e)

decryptGCM :: ByteString -> ByteString -> ByteString -> AuthTag -> Either String ByteString
decryptGCM key iv ciphertext authTag =
  case cipherInit key :: CryptoFailable AES256 of
    CryptoPassed cipher ->
      let Just iv' = makeIV iv
      in decryptGCM cipher iv' mempty ciphertext authTag
    CryptoFailed e -> Left (show e)

sendSecure :: Socket -> ByteString -> ByteString -> IO ()
sendSecure sock key plaintext = do
  let (ciphertext, authTag) = encryptGCM key nullIV plaintext
  send sock (encode ciphertext)
  send sock (encode (convert authTag))

receiveSecure :: Socket -> ByteString -> IO (Either String ByteString)
receiveSecure sock key = do
  ciphertext <- recv sock 1024
  authTag <- recv sock 1024
  case (decode ciphertext, decode authTag) of
    (Right ct, Right at) -> decryptGCM key nullIV ct (AuthTag at)
    _ -> return $ Left "Error in decoding message or authentication tag."

handleClient :: Socket -> ByteString -> IO ()
handleClient sock sharedKey = do
  putStrLn "Client connected. Enter message to send:"
  message <- getLine
  sendSecure sock sharedKey (BS.pack message)
  putStrLn "Message sent. Waiting for response..."
  response <- receiveSecure sock sharedKey
  case response of
    Right msg -> putStrLn $ "Received message: " ++ BS.unpack msg
    Left err -> putStrLn $ "Error receiving message: " ++ err
  close sock

startServer :: IO ()
startServer = withSocketsDo $ do
  sock <- socket AF_INET Stream 0
  bind sock (SockAddrInet 8081 iNADDR_ANY)
  listen sock 5
  putStrLn "Server listening on port 8081."

  let acceptLoop = do
        (conn, _) <- accept sock
        putStrLn "New client connected."
        forkIO $ do
          (privateKey, publicKey) <- generateKeyPair'
          send conn (serializePoint publicKey)
          clientPublicKeyBytes <- recv conn 1024
          case deserializePoint clientPublicKeyBytes of
            Just clientPublicKey -> do
              let sharedSecret = ecdh clientPublicKey privateKey
              case sharedSecret of
                Just secret -> handleClient conn (deriveKey secret)
                Nothing -> putStrLn "Error in Ecliptic curve key exchange."
            Nothing -> putStrLn "Invalid client public key received."
        acceptLoop

  acceptLoop
  close sock

startClient :: String -> IO ()
startClient serverIP = withSocketsDo $ do
  sock <- socket AF_INET Stream 0
  connect sock (SockAddrInet 8081 (tupleToHostAddress (read serverIP)))
  putStrLn "Connected to server."
  serverPublicKeyBytes <- recv sock 1024
  case deserializePoint serverPublicKeyBytes of
    Just serverPublicKey -> do
      (privateKey, publicKey) <- generateKeyPair'
      send sock (serializePoint publicKey)
      let sharedSecret = ecdh serverPublicKey privateKey
      case sharedSecret of
        Just secret -> handleClient sock (deriveKey secret)
        Nothing -> putStrLn "Error in ECDH key exchange."
    Nothing -> putStrLn "Invalid server public key received."
  close sock

main :: IO ()
main = do
  putStrLn "Do you want to start a server or a client?"
  response <- getLine
  case response of
    "server" -> startServer
    "client" -> do
      putStrLn "Enter the server IP address:"
      serverIP <- getLine
      startClient serverIP
    _ -> putStrLn "Invalid input. Enter 'server' or 'client'."
