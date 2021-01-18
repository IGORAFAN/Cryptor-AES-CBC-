#include <iostream>

#include "MyCryptor.h"

#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/sha.h"


int main(){
    std::string pass = "pass";

    const std::string chipherTextPath = "D:\\Projects\\C++\\AES(OpenSSL)\\x64\\Debug\\chipher_text";
    const std::string decryptedTextPath = "D:\\Projects\\C++\\AES(OpenSSL)\\x64\\Debug\\DecryptedText.txt";

    MyCryptor myCryptor;

    try{
        OpenSSL_add_all_algorithms();
        myCryptor.PasswordToKey(pass);
        myCryptor.SetChipherTextPath(chipherTextPath);
        myCryptor.SetDecryptedTextPath(decryptedTextPath);
        myCryptor.Decrypt();
        std::cout << "Text was decrypted" << std::endl;
        std::cin.get();
    }
    catch (const std::runtime_error& ex){
        std::cerr << ex.what();
    }
}