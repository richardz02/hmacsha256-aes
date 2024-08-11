#include "../inc/crypto.hpp"
#include <cryptopp/secblockfwd.h>

void generate_hmac_key(CryptoPP::SecByteBlock& key) {
    CryptoPP::AutoSeededRandomPool rng;

    rng.GenerateBlock(key, key.size());
}

std::string HMACSHA256(std::string& file_content, CryptoPP::SecByteBlock& key) {

    std::string encoded, mac;

    try {
        CryptoPP::HMAC < CryptoPP::SHA256 > hmac (key, key.size());
        CryptoPP::StringSource ss(file_content, true,
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

void generate_aes_key(CryptoPP::SecByteBlock &key) {
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());
}

std::string aes_encrypt(const std::string& file_content, CryptoPP::SecByteBlock& key) {
    std::string cipher, encoded;

    try {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
        e.SetKey(key, key.size());

        CryptoPP::StringSource ss1(file_content, true,
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
    std::cout << "Cipher text (in hex): \n" << encoded << std::endl;

    return cipher;
}

std::string aes_decrypt(const std::string& file_content, CryptoPP::SecByteBlock& key) {
    std::string original, decoded;

     try {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
        d.SetKey(key, key.size());

        CryptoPP::StringSource ss1(file_content, true,
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(original)
            )
        );
    } catch (CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    std::cout << "Original text: \n" << original << std::endl;

    return original;
}
