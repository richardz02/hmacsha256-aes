#include "../inc/crypto.hpp"

#include <fstream>
#include <iterator>

// Stores file contents in a string to use as buffer
std::string store_file_contents(const std::string& file_path);


int main() {

    CryptoPP::SecByteBlock key(16);
    generate_hmac_key(key);

    std::string filePath = "../message.txt";
    std::string hash = HMACSHA256(filePath, key);
    std::cout << "hash of the message is: \n" << hash << std::endl;

    std::string file_content = store_file_contents(filePath);
    std::cout << "Read file content: \n" << file_content << std::endl;

    CryptoPP::SecByteBlock aes_key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    generate_aes_key(aes_key);

    std::string cipher_text = aes_encrypt(file_content, aes_key);
    std::string original_text = aes_decrypt(cipher_text, aes_key);


    return 0;
    
}

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
