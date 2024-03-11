## HMACSHA256-AES Project

This project will simulate the interaction between a client and a server using AES encryption for data protection, and Hmac-sha256 for verifying the authenticity of data.

Imagine this, a client is trying to send a message to a server. Both the client and server share a secret key for hmac-sha256, and they also share a secret key for AES.

- The client first calculates the hash of the message using the hmac algorithm, then encrypts the message with AES key. Then the client sends the hash and the encrypted message over to the server.
- The server receives the encryped message and the hash. The server decrypts the message using the shared AES key, and also calculates the hash from the message. The hashes are compared. If they match, that means the message hasn't been tampered.

This project using the CryptoPP library for any hashing, encryption, and decryption.

We will be using AES - EBC mode for the encryption and decryption. Since EBC mode provides only confidentiality and not authenticity, this is where the HMAC will come in to verify the authenticity of the message.
