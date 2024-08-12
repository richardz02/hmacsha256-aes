#include "../inc/crypto.hpp"

#include <cryptopp/secblockfwd.h>
#include <fstream>
#include <iterator>


int main() {

    // Get message from user input
    std::cout << "Enter a message: " << std::endl;
    std::string message;
    getline(std::cin, message);
    std::cout << "You entered: " << message << std::endl;

    // Read hmac key and generate hash
    CryptoPP::SecByteBlock hmac_key = read_key("../cryptography/hmac-key.txt");

    std::string hash = HMACSHA256(message, hmac_key);
    std::cout << "hash of the message is: \n" << hash << "(written to file)" << std::endl;
    std::ofstream hash_file("../hash.txt");
    hash_file << hash;
    hash_file.close();

    // Read aes key and encrypt message
    CryptoPP::SecByteBlock aes_key = read_key("../cryptography/aes-key.txt");
    std::string cipher_text = aes_encrypt(message, aes_key);

    // Write encrypted message to file
    std::ofstream out("../message.txt");
    out << cipher_text;
    out.close();

    return 0;
}

