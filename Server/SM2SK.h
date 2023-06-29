#pragma once
#include <iostream>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <iomanip>
#include <string>
#pragma warning (disable : 4996)

//void performSM2KeyExchange()
//{
//    // 初始化OpenSSL库
//    OpenSSL_add_all_algorithms();
//
//    // 创建EC_KEY对象
//    EC_KEY* ecKey1 = EC_KEY_new_by_curve_name(NID_sm2);
//    EC_KEY* ecKey2 = EC_KEY_new_by_curve_name(NID_sm2);
//
//    // 生成密钥对
//    if (EC_KEY_generate_key(ecKey1) != 1)
//    {
//        std::cout << "Failed to generate SM2 key pair 1." << std::endl;
//        EC_KEY_free(ecKey1);
//        EC_KEY_free(ecKey2);
//        return;
//    }
//
//    if (EC_KEY_generate_key(ecKey2) != 1)
//    {
//        std::cout << "Failed to generate SM2 key pair 2." << std::endl;
//        EC_KEY_free(ecKey1);
//        EC_KEY_free(ecKey2);
//        return;
//    }
//
//    // 执行密钥交换
//    unsigned char* shared_secret1 = new unsigned char[EVP_MAX_MD_SIZE];
//    unsigned char* shared_secret2 = new unsigned char[EVP_MAX_MD_SIZE];
//    size_t shared_secret_len1, shared_secret_len2;
//
//    shared_secret_len1 = ECDH_compute_key(shared_secret1, EVP_MAX_MD_SIZE, EC_KEY_get0_public_key(ecKey2), ecKey1, NULL);
//    shared_secret_len2 = ECDH_compute_key(shared_secret2, EVP_MAX_MD_SIZE, EC_KEY_get0_public_key(ecKey1), ecKey2, NULL);
//
//    // 输出共享密钥
//    std::cout << "Shared Secret 1: ";
//    for (size_t i = 0; i < shared_secret_len1; i++)
//    {
//        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(shared_secret1[i]);
//    }
//    std::cout << std::endl;
//
//    std::cout << "Shared Secret 2: ";
//    for (size_t i = 0; i < shared_secret_len2; i++)
//    {
//        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(shared_secret2[i]);
//    }
//    std::cout << std::endl;
//
//    // 清理资源
//    delete[] shared_secret1;
//    delete[] shared_secret2;
//    EC_KEY_free(ecKey1);
//    EC_KEY_free(ecKey2);
//
//    // 清理OpenSSL库
//    EVP_cleanup();
//}





std::string UCharToString(unsigned char* Input, size_t Len) {
    std::string Key = "";
    char* B = new char[Len * 2 + 1](); // B 数组的指针，长度为 len*2，多出的一个字节是字符串结束符 '\0'
    for (int i = 0; i < Len; i++) {
        sprintf(&B[i * 2], "%02X", Input[i]); // 将 A[i] 转换为两个十六进制字符，存储到 B 数组中
    }
    B[Len * 2] = '\0'; // 添加字符串结束符

    for (int i = 0; i < Len * 2 + 1; i++) {
        Key = Key + B[i];
    }

    return Key;
}




//std::string UCharToString(const unsigned char* data, size_t length) {
//    if (data == nullptr || length == 0) {
//        return std::string();
//    }
//
//    return std::string(reinterpret_cast<const char*>(data), length);
//}

EC_KEY* generateECKey(int randomNum) {
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_sm2);
    if (ecKey == nullptr) {
        // 处理密钥生成失败的情况
        // ...
        return nullptr;
    }

    BIGNUM* bn = BN_new();
    BN_set_word(bn, randomNum);
    if (EC_KEY_set_private_key(ecKey, bn) != 1) {
        // 处理密钥设置失败的情况
        // ...
        EC_KEY_free(ecKey);
        BN_free(bn);
        return nullptr;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    EC_POINT* pub_key = EC_POINT_new(group);
    if (EC_POINT_mul(group, pub_key, bn, NULL, NULL, NULL) != 1) {
        // 处理公钥计算失败的情况
        // ...
        EC_POINT_free(pub_key);
        EC_KEY_free(ecKey);
        BN_free(bn);
        return nullptr;
    }

    if (EC_KEY_set_public_key(ecKey, pub_key) != 1) {
        // 处理公钥设置失败的情况
        // ...
        EC_POINT_free(pub_key);
        EC_KEY_free(ecKey);
        BN_free(bn);
        return nullptr;
    }

    EC_POINT_free(pub_key);
    BN_free(bn);

    return ecKey;
}

std::string SM2KeyExchange(int a, int b) {
    // 初始化OpenSSL库
    OpenSSL_add_all_algorithms();

    // 设置随机数种子
    unsigned char seed[8];
    seed[0] = a & 0xFF;
    seed[1] = (a >> 8) & 0xFF;
    seed[2] = (a >> 16) & 0xFF;
    seed[3] = (a >> 24) & 0xFF;
    seed[4] = b & 0xFF;
    seed[5] = (b >> 8) & 0xFF;
    seed[6] = (b >> 16) & 0xFF;
    seed[7] = (b >> 24) & 0xFF;
    RAND_seed(seed, sizeof(seed));

    // 生成EC_KEY* ecKey1
    EC_KEY* ecKey1 = generateECKey(a);
    if (ecKey1 == nullptr) {
        // 处理密钥生成失败的情况
        // ...
        EVP_cleanup();
        return "ERROR";
    }

    // 生成EC_KEY* ecKey2
    EC_KEY* ecKey2 = generateECKey(b);
    if (ecKey2 == nullptr) {
        // 处理密钥生成失败的情况
        // ...
        EC_KEY_free(ecKey1);
        EVP_cleanup();
        return "ERROR";
    }

    // 执行密钥交换
    unsigned char shared_secret[EVP_MAX_MD_SIZE];
    size_t shared_secret_len1, shared_secret_len2;

    shared_secret_len1 = ECDH_compute_key(shared_secret, EVP_MAX_MD_SIZE, EC_KEY_get0_public_key(ecKey2), ecKey1, NULL);
    shared_secret_len2 = ECDH_compute_key(shared_secret, EVP_MAX_MD_SIZE, EC_KEY_get0_public_key(ecKey1), ecKey2, NULL);

    // 输出共享密钥
    std::string key = UCharToString(shared_secret, shared_secret_len1);

    EC_KEY_free(ecKey1);
    EC_KEY_free(ecKey2);
    EVP_cleanup();

    return key;
}
