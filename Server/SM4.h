#pragma once
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <string>
#include <iomanip>

void printHex(const unsigned char* buffer, int length)
{
    for (int i = 0; i < length; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }
    std::cout << std::dec << std::endl;
}


// SM4 �ӽ��ܺ���
int SM4EncryptDecrypt(const unsigned char* in, size_t inLen, unsigned char* out, const unsigned char* key, int enc) {
    const EVP_CIPHER* cipher = nullptr;
    if (enc) {
        cipher = EVP_sm4_ecb();
    }
    else {
        cipher = EVP_sm4_ecb();
    }
    // �����ӽ���������
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return -1;
    }
    // ��ʼ��������
    if (EVP_CipherInit(ctx, cipher, key, nullptr, enc) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    // ���ܻ����
    int outLen = 0;
    if (EVP_CipherUpdate(ctx, out, &outLen, in, inLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    // ��β����
    int finalOutLen = 0;
    if (EVP_CipherFinal(ctx, out + outLen, &finalOutLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    outLen += finalOutLen;
    // �ͷ�������
    EVP_CIPHER_CTX_free(ctx);
    return outLen;
}