#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <cryptopp/secblockfwd.h>
#include <iostream>
#include <fstream>
#include <string>
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/hmac.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"

// Stores file contents in a string to use as buffer
std::string store_file_contents(const std::string& file_path);

// Hmac Key Generation
void generate_hmac_key();

// Performs HMAC-SHA256 and returns HMAC
std::string HMACSHA256(std::string& file_content, CryptoPP::SecByteBlock& key);

// Generate key for AES encryption/decryption
void generate_aes_key();

// Read keys from file
CryptoPP::SecByteBlock read_key(const std::string&& file_name);

// AES-ECB encryption
std::string aes_encrypt(const std::string& file_content, CryptoPP::SecByteBlock& key);

// AES-ECB decryption
std::string aes_decrypt(const std::string& file_content, CryptoPP::SecByteBlock& key);


#endif // CRYPTO_HPP
