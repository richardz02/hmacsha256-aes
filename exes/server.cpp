#include "../inc/crypto.hpp"
#include <cryptopp/secblockfwd.h>

int main() {

    // Server asks for user input (path to encrypted file)
    std::cout << "Enter the full path to the message file: ";
    std::string message_file;
    getline(std::cin, message_file);

    std::cout << "Enter the full path to the hash file: ";
    std::string hash_file;
    getline(std::cin, hash_file);
    printf("\n");

    // Server reads file content from file path
    std::string message = store_file_contents(message_file);

    // Decrypt the file and hash the message to see if hashes match
    CryptoPP::SecByteBlock aes_key = read_key("../cryptography/aes-key.txt");
    std::string original = aes_decrypt(message, aes_key);

    CryptoPP::SecByteBlock hmac_key = read_key("../cryptography/hmac-key.txt");
    std::string server_hash = HMACSHA256(original, hmac_key);
    std::cout << "\nHash is: " << server_hash << std::endl;

    // Provide security checks for hash (match vs no match)
    std::string client_hash = store_file_contents(hash_file);
    if (server_hash == client_hash) {
        std::cout << "Message is original!" << std::endl;
    } else {
        std::cout << "MESSAGE HAS BEEN TAMPERED!" << std::endl;
    }


    return 0;
}
