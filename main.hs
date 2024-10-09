{-# LANGUAGE OverloadedStrings #-}

module ECDHChat where

import Crypto.Error (CryptoFailable)
import Crypto.Number.Serialize (os2ip, ip2os)
import Crypto.PubKey.ECC (Curve, getCurveByName, generateKeyPair)
import Crypto.PubKey.ECC.Types (Point, getPointX, getPointY)
import Data.ByteArray (ByteArrayAccess, convert)
import Data.ByteString (ByteString)
import Data.String (fromString)
import Crypto.Hash (hashWith, SHA256)
import Crypto.Cipher.AES (AES256, encrypt, decrypt)
import Data.ByteString.Base64 (encode, decode)
import Network (listenOn, accept, PortID(..))
import Network.Socket (Socket, socket, bindSocket, listen, accept, recv, send, close)
import System.IO (hPutStrLn, hGetLine)

curve :: Curve
curve = getCurveByName "secp256k1"

generateKeyPair' :: IO (Point, Point) -- | Generate key pair
generateKeyPair' = generateKeyPair curve

serializePoint :: Point -> ByteString -- | Serialize point to ByteString
serializePoint point = os2ip $ getPointX point ++ getPointY point

deserializePoint :: ByteString -> Point -- | Deserialize ByteString to  point
deserializePoint bytes = let (x, y) = ip2os bytes in point x y

ecdh :: Point -> Point -> IO ByteString -- | ECDH key exchange
ecdh publicKey privateKey = do
  let sharedSecret = multiply curve privateKey publicKey
  return $ serializePoint sharedSecret

multiply :: Curve -> Point -> Point -> Point -- | Multiply a point by scalar
multiply curve scalar point = 
  let scalarBytes = serializePoint scalar
      pointBytes = serializePoint point
      resultBytes = multiplyBytes curve scalarBytes pointBytes
  in deserializePoint resultBytes
  where
    multiplyBytes :: Curve -> ByteString -> ByteString -> ByteString
    multiplyBytes curve scalarBytes pointBytes = 
      let scalarInt = os2ip scalarBytes
          pointInt = os2ip pointBytes
          resultInt = (scalarInt * pointInt) `mod` (curveGetSize curve)
      in ip2os resultInt

hash :: ByteString -> ByteString -- | Hash a ByteString using SHA-256
hash bytes = 
  let hashBytes = hashWith SHA256 bytes
  in convert hashBytes

deriveKey :: ByteString -> ByteString -- | Derive a symmetric key from a shared secret
deriveKey sharedSecret = hash sharedSecret

encrypt :: ByteString -> ByteString -> ByteString -- | Encrypt message
encrypt key message = 
  let iv = "0000000000000000"
      encryptedBytes = encryptAES256 key iv message
  in encode encryptedBytes
  where
    encryptAES256 :: ByteString -> ByteString -> ByteString -> ByteString
    encryptAES256 key iv message = 
      let cipher = AES256 key
          encryptedBytes = encrypt cipher iv message
      in encryptedBytes

decrypt :: ByteString -> ByteString -> ByteString -- | Decrypt a message using a symmetric key
decrypt key ciphertext = 
  let iv = "0000000000000000"
      decryptedBytes = decryptAES256 key iv ciphertext
  in decryptedBytes
  where
    decryptAES256 :: ByteString -> ByteString -> ByteString -> ByteString
    decryptAES256 key iv ciphertext = 
      let cipher = AES256 key
          decryptedBytes = decrypt cipher iv ciphertext
      in decryptedBytes

handleConnection :: Socket -> String -> IO () -- | Handle incoming connections
handleConnection sock username = do
  (user-1PrivateKey, user-1PublicKey) <- generateKeyPair'
  let user-1PublicKeyBytes = serializePoint user-1PublicKey
  send sock user-1PublicKeyBytes
  user-2PublicKeyBytes <- recv sock 1024
  let user-2PublicKey = deserializePoint user-2PublicKeyBytes
  let user-1SharedSecret = ecdh user-2PublicKey user-1PrivateKey
  let user-1SymmetricKey = deriveKey user-1SharedSecret
  putStrLn $ "Connected to " ++ username ++ ". Enter a message to send:"
  message <- getLine
  let encryptedMessage = encrypt user-1SymmetricKey (fromString message)
  send sock encryptedMessage
  putStrLn "Waiting for response..."
  user-2EncryptedMessage <- recv sock 1024
  let decryptedMessage = decrypt user-1SymmetricKey user-2EncryptedMessage
  putStrLn $ username ++ ": " ++ show decryptedMessage 

-- | Start the server
startServer :: IO ()
startServer = do
  putStrLn "Enter your username:"
  username <- getLine
  putStrLn "Waiting for incoming connections..."
  sock <- socket AF_INET Stream 0
  bindSocket sock (SockAddrInet 8080 iNADDR_ANY)
  listen sock 1
  (connSock, _) <- accept sock
  putStrLn "Connected to client."
  handleConnection connSock username
  close connSock

-- | Start the client
startClient :: IO ()
startClient = do
  putStrLn "Enter your username:"
  username <- getLine
  putStrLn "Enter the server's username:"
  serverUsername <- getLine
  putStrLn "Connecting to server..."
  sock <- socket AF_INET Stream 0
  connect sock (SockAddrInet 8080 iNADDR_ANY)
  putStrLn "Connected to server. Waiting for public key..."
  user-1PublicKeyBytes <- recv sock 1024
  let user-1PublicKey = deserializePoint user-1PublicKeyBytes
  (user-2PrivateKey, user-2PublicKey) <- generateKeyPair'
  let user-2PublicKeyBytes = serializePoint user-2PublicKey
  send sock user-2PublicKeyBytes
  user-1SharedSecret <- ecdh user-1PublicKey user-2PrivateKey
  let user-2SymmetricKey = deriveKey user-1SharedSecret
  putStrLn $ "Connected to " ++ serverUsername ++ ". Enter a message to send:"
  message <- getLine
  let encryptedMessage = encrypt user-2SymmetricKey (fromString message)
  send sock encryptedMessage
  putStrLn "Waiting for response..."
  user-1EncryptedMessage <- recv sock 1024
  let decryptedMessage = decrypt user-2SymmetricKey user-1EncryptedMessage
  putStrLn $ serverUsername ++ ": " ++ show decryptedMessage

main :: IO ()
main = do
  putStrLn "Do you want to start as a server or client?"
  response <- getLine
  if response == "server" then startServer else startClient
