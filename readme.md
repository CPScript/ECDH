## Features

* Secure key exchange using ECDH protocol
* Symmetric encryption using AES-256
* Simple chat interface for sending and receiving messages

## Requirements

* Haskell compiler (e.g. GHC)
* `crypto` and `network` libraries

## Usage

1. Compile the code using `ghc ECDHChat.hs`
2. Run the server using `./ECDHChat server`
3. Run the client using `./ECDHChat client`
4. Follow the prompts to enter your username and the server's username
5. Send and receive messages securely using the chat interface

## Warnings:

> * This is a basic implementation and does not include any error handling or security measures beyond the ECDH key exchange protocol... Sorry <3
> * The application uses a simple symmetric encryption scheme and does not provide any authentication or authorization mechanisms.
> * This code is for educational purposes only and should not be used in production without further development and testing.

## extra
* Made by - CPScript
* This code is released under the MIT License. See LICENSE for details.
