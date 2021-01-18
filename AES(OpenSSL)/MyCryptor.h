#pragma once
#include <string>
#include <vector>
#include <iterator>

#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/sha.h"


class MyCryptor {
public:
    bool SetPlainTextPath(const std::string& path);
    bool SetChipherTextPath(const std::string& path);
    bool SetDecryptedTextPath(const std::string& path);

    void ReadFile(const std::string& filePath, std::vector<unsigned char>& buf);
    void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf);
    void AppendToFile(const std::string& filePath, const std::vector<unsigned char>& buf);

    void PasswordToKey(std::string& password);
    void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash);

    void EncryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText);
    void DecryptAes(const std::vector<unsigned char> chipherText, std::vector<unsigned char>& decryptedText);

    void Encrypt();
    void Decrypt();

private:
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    std::string m_plainTextPath;
    std::string m_chipherTextPath;
    std::string m_decryptedTextPath;

    std::vector<unsigned char> m_plainText;
    std::vector<unsigned char> m_chipherText;
    std::vector<unsigned char> m_decryptedText;

    std::vector<unsigned char> m_hashSumOfPlainText;
};