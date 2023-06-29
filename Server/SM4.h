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


// SM4 加解密函数
int SM4EncryptDecrypt(const unsigned char* in, size_t inLen, unsigned char* out, const unsigned char* key, int enc) {
    const EVP_CIPHER* cipher = nullptr;
    if (enc) {
        cipher = EVP_sm4_ecb();
    }
    else {
        cipher = EVP_sm4_ecb();
    }
    // 创建加解密上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return -1;
    }
    // 初始化上下文
    if (EVP_CipherInit(ctx, cipher, key, nullptr, enc) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    // 加密或解密
    int outLen = 0;
    if (EVP_CipherUpdate(ctx, out, &outLen, in, inLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    // 结尾处理
    int finalOutLen = 0;
    if (EVP_CipherFinal(ctx, out + outLen, &finalOutLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    outLen += finalOutLen;
    // 释放上下文
    EVP_CIPHER_CTX_free(ctx);
    return outLen;
}