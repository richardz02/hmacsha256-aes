#include <iostream>
#include <fstream>
#include <string>
#include "cryptopp/hmac.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"

// Hmac Key Generation
void generate_hmac_key(CryptoPP::SecByteBlock& key, size_t KEYSIZE);

// Performs HMAC-SHA256 and returns HMAC
std::string HMACSHA256(std::string& filePath, CryptoPP::SecByteBlock& key);


int main() {

    // Generates hmac key
    CryptoPP::SecByteBlock key(16);
    generate_hmac_key(key, 16);

    std::string filePath = "message.txt";
    std::string hash = HMACSHA256(filePath, key);

    std::cout << "hash of the message is: \n" << hash << std::endl;

    return 0;
    
}

// Function Definitions

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