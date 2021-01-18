#include <exception>
#include <iostream>
#include <fstream>

#include "MyCryptor.h"

bool MyCryptor::SetPlainTextPath(const std::string& path){
    if (path.empty()) {
        throw std::exception("DecryptedTextPath is empty!");
        return false;
    }
    else {
        m_plainTextPath = path;
        return true;
    }
}

bool MyCryptor::SetChipherTextPath(const std::string& path){
    if (path.empty()) {
        throw std::exception("DecryptedTextPath is empty!");
        return false;
    }
    else {
        m_chipherTextPath = path;
        return true;
    }
}

bool MyCryptor::SetDecryptedTextPath(const std::string& path){
    if (path.empty()) {
        throw std::exception("DecryptedTextPath is empty!");
        return false;
    }
    else {
        m_decryptedTextPath = path;
        return true;
    }
}

void MyCryptor::ReadFile(const std::string& filePath, std::vector<unsigned char>& buf) {
    std::basic_fstream<unsigned char> fileStream(filePath, std::ios::binary | std::fstream::in);
    if (!fileStream.is_open()) {
        throw std::runtime_error("Can not open file " + filePath);
    }

    buf.clear();
    buf.insert(buf.begin(), std::istreambuf_iterator<unsigned char>(fileStream), std::istreambuf_iterator<unsigned char>());

    fileStream.close();
}

void MyCryptor::WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf) {
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}

void MyCryptor::AppendToFile(const std::string& filePath, const std::vector<unsigned char>& buf) {
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary | std::ios::app);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}

void MyCryptor::PasswordToKey(std::string& password) {
    const EVP_MD* dgst = EVP_get_digestbyname("md5");
    if (!dgst) {
        throw std::runtime_error("no such digest");
    }

    const unsigned char* salt = NULL;
    if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
        reinterpret_cast<unsigned char*>(&password[0]),
        password.size(), 1, key, iv)) {
        throw std::runtime_error("EVP_BytesToKey failed");
    }
}

void MyCryptor::CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash) {
    std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &data[0], data.size());
    SHA256_Final(&hashTmp[0], &sha256);

    hash.swap(hashTmp);
}

void MyCryptor::EncryptAes(const std::vector<unsigned char> fromPlainText, std::vector<unsigned char>& toChipherText) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))  {
        throw std::runtime_error("EncryptInit error");
    }

    std::vector<unsigned char> chipherTextBuf(m_plainText.size() + AES_BLOCK_SIZE);
    int chipherTextSize = 0;
    if (!EVP_EncryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &m_plainText[0], m_plainText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encrypt error");
    }

    int lastPartLen = 0;
    if (!EVP_EncryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal error");
    }
    chipherTextSize += lastPartLen;
    chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

    m_chipherText.swap(chipherTextBuf);

    EVP_CIPHER_CTX_free(ctx);
}

void MyCryptor::DecryptAes(const std::vector<unsigned char> fromChipherText, std::vector<unsigned char>& toDecryptedText) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        throw std::runtime_error("EncryptInit error");
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    std::vector<unsigned char> decryptedTextBuf(m_chipherText.size() + AES_BLOCK_SIZE);
    int decryptedTextSize = 0;
    if (!EVP_DecryptUpdate(ctx, &decryptedTextBuf[0], &decryptedTextSize, &m_chipherText[0], m_chipherText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encrypt error");
    }

    int lastPartLen = 0;
    if (!EVP_DecryptFinal_ex(ctx, &decryptedTextBuf[0] + decryptedTextSize, &lastPartLen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal error");
    }
    decryptedTextSize += lastPartLen;
    decryptedTextBuf.erase(decryptedTextBuf.begin() + decryptedTextSize, decryptedTextBuf.end());

    m_decryptedText.swap(decryptedTextBuf);

    EVP_CIPHER_CTX_free(ctx);
}

void MyCryptor::Encrypt() {
    ReadFile(m_plainTextPath, m_plainText);

    CalculateHash(m_plainText, m_hashSumOfPlainText);

    EncryptAes(m_plainText, m_chipherText);

    WriteFile(m_chipherTextPath, m_chipherText);

    AppendToFile(m_chipherTextPath, m_hashSumOfPlainText);
}

void MyCryptor::Decrypt() {
    ReadFile(m_chipherTextPath, m_chipherText);

    std::vector<unsigned char> hashSumOfChipherText(m_chipherText.begin() + (m_chipherText.size() - SHA256_DIGEST_LENGTH), m_chipherText.end());
    m_chipherText.resize(m_chipherText.size() - SHA256_DIGEST_LENGTH);

    DecryptAes(m_chipherText, m_decryptedText);

    m_decryptedText.resize(m_decryptedText.size() - 1);

    std::vector<unsigned char> hashSumOfDecryptedText;
    CalculateHash(m_decryptedText, hashSumOfDecryptedText);

    if (hashSumOfChipherText != hashSumOfDecryptedText) {
        throw std::runtime_error("Decrypted file is corrupted");
    }

    WriteFile(m_decryptedTextPath, m_decryptedText);
}
