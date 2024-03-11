#include <iostream>
#include <fstream>
#include <string>
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/hmac.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"

// Generate key for AES encryption/decryption
void generate_aes_key(CryptoPP::SecByteBlock& key);

// AES-ECB encryption
std::string AES_ECB_encryption(std::string& filePath, CryptoPP::SecByteBlock& key);

// Hmac Key Generation
void generate_hmac_key(CryptoPP::SecByteBlock& key, size_t KEYSIZE);

// Performs HMAC-SHA256 and returns HMAC
std::string HMACSHA256(std::string& filePath, CryptoPP::SecByteBlock& key);


int main() {

    // CryptoPP::SecByteBlock key(16);
    // generate_hmac_key(key, 16);

    // std::string filePath = "message.txt";
    // std::string hash = HMACSHA256(filePath, key);

    // std::cout << "hash of the message is: \n" << hash << std::endl;

    std::string filePath = "message.txt";
    CryptoPP::SecByteBlock aes_key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    generate_aes_key(aes_key);
    std::string cipher_text = AES_ECB_encryption(filePath, aes_key);

    std::cout << cipher_text << std::endl;

    return 0;
    
}


void generate_aes_key(CryptoPP::SecByteBlock &key) {
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());
}

std::string AES_ECB_encryption(std::string& filePath, CryptoPP::SecByteBlock& key) {
    std::string plain_text, cipher, encoded;

    // Read contents from the file and place it in a string
    CryptoPP::FileSource file(filePath.c_str(), true, 
        new CryptoPP::StringSink(plain_text)
    );

    try {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
        e.SetKey(key, key.size());

        CryptoPP::StringSource ss1(plain_text, true, 
            new CryptoPP::StreamTransformationFilter(e, 
                new CryptoPP::StringSink(cipher)
            )
        );
    } catch (CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    // Pretty print cipher text
    CryptoPP::StringSource ss2( cipher, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    std::cout << "cipher text: " << encoded << std::endl;

    return cipher;
}

void generate_hmac_key(CryptoPP::SecByteBlock& key, size_t KEYSIZE) {
    CryptoPP::AutoSeededRandomPool rng;

    rng.GenerateBlock(key, key.size());
}

std::string HMACSHA256(std::string& filePath, CryptoPP::SecByteBlock& key) {
    std::ifstream file;
    file.open(filePath);

    if (!file.is_open()) {
        std::cout << "Error opening file: " << filePath << std::endl;
        exit(1);
    }

    std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    std::string encoded, mac;

    try {
        CryptoPP::HMAC < CryptoPP::SHA256 > hmac (key, key.size());
        CryptoPP::StringSource ss(fileContent, true,
            new CryptoPP::HashFilter(hmac,
                new CryptoPP::StringSink(mac)
            )
        );
    } catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    // print out HMAC
    encoded.clear();
    CryptoPP::StringSource ss2(mac, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded)
        )
    );

    return encoded;
}