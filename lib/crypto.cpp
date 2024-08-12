#include "../inc/crypto.hpp"
#include <cryptopp/config_int.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblockfwd.h>
#include <cryptopp/base64.h>

std::string store_file_contents(const std::string& file_path) {
   std::ifstream file;
   file.open(file_path);

   if(!file.is_open()) {
       std::cerr << "Error opening file: " << file_path << std::endl;
       exit(1);
   }

   // Avoid using iterator method to read large files, as it is surprisingly inefficient (buffer would be better)
   std::string file_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
   file.close();

   return file_content;
}

void generate_hmac_key() {
    CryptoPP::SecByteBlock key(16);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(key, key.size());

    std::string file_name = "../cryptography/hmac-key.txt";

    CryptoPP::StringSource(key.data(), key.size(), true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::FileSink(file_name.c_str()), false
        )
    );
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

    // Encode HMAC
    encoded.clear();
    CryptoPP::StringSource ss2(mac, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded)
        )
    );

    return encoded;
}

void generate_aes_key() {
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());

    std::string file_name = "../cryptography/aes-key.txt";

    CryptoPP::StringSource(key.data(), key.size(), true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::FileSink(file_name.c_str()), false
        )
    );
}

CryptoPP::SecByteBlock read_key(const std::string&& file_name) {
    std::string base64Key;

    CryptoPP::FileSource(file_name.c_str(), true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(base64Key)
        )
    );

    CryptoPP::SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(base64Key.data()), base64Key.size());
    return key;
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

    // Print ciphertext in Base64 format
    CryptoPP::StringSource ss2( cipher, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink( encoded )
        )
    );

    std::cout << "Cipher text (in base64): " << encoded << std::endl;

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

    std::cout << "Original text: " << original << std::endl;

    return original;
}
