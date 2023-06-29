#pragma once
#include <iostream>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "SM2SK.h"
#include <vector>
#pragma warning (disable : 4996)

//unsigned char* SM2Signature(unsigned char* data)
//{
//    // 初始化OpenSSL库
//    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
//
//    // 创建EC_KEY对象
//    EC_KEY* ecKey = EC_KEY_new();
//    if (ecKey == nullptr)
//    {
//        std::cout << "Failed to create EC_KEY object." << std::endl;
//        return;
//    }
//
//    // 设置椭圆曲线参数
//    const EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
//    if (group == nullptr)
//    {
//        std::cout << "Failed to create EC_GROUP object." << std::endl;
//        EC_KEY_free(ecKey);
//        return;
//    }
//    EC_KEY_set_group(ecKey, group);
//
//    // 生成密钥对
//    if (EC_KEY_generate_key(ecKey) != 1)
//    {
//        std::cout << "Failed to generate SM2 key pair." << std::endl;
//        EC_KEY_free(ecKey);
//        EC_GROUP_free((EC_GROUP*)group);
//        return;
//    }
//
//    // 获取待签名的数据
//    size_t data_len = strlen((const char*)data);
//
//    // 创建ECDSA_SIG对象
//    ECDSA_SIG* signature = ECDSA_do_sign(data, data_len, ecKey);
//    if (signature == nullptr)
//    {
//        std::cout << "Failed to create ECDSA_SIG object." << std::endl;
//        EC_KEY_free(ecKey);
//        EC_GROUP_free((EC_GROUP*)group);
//        return;
//    }
//
//    // 序列化签名
//    unsigned char* der_signature = NULL;
//    int der_signature_len = i2d_ECDSA_SIG(signature, &der_signature);
//
//    // 输出序列化后的签名
//    std::cout << "Serialized Signature: ";
//    //for (int i = 0; i < der_signature_len; i++)
//    //{
//    //    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(der_signature[i]);
//    //}
//    //std::cout << std::endl;
//    // 
//    // 清理资源
//    EC_KEY_free(ecKey);
//    EC_GROUP_free((EC_GROUP*)group);
//    ECDSA_SIG_free(signature);
//    OPENSSL_free(der_signature);
//    OPENSSL_cleanup();
//
//    return der_signature;
//
//}
//
//
//{
//    // 验证签名
//    int verification_result = ECDSA_do_verify(data, data_len, signature, ecKey);
//
//    // 输出验证结果
//    if (verification_result == 1)
//    {
//        std::cout << "Signature is valid." << std::endl;
//    }
//    else if (verification_result == 0)
//    {
//        std::cout << "Signature is invalid." << std::endl;
//    }
//    else
//    {
//        std::cout << "Signature verification error." << std::endl;
//    }
//
//    // 清理资源
//    EC_KEY_free(ecKey);
//    EC_GROUP_free((EC_GROUP*)group);
//
//
//    // 清理OpenSSL库
//}



std::string uchar_to_string(const unsigned char* data, size_t len) {
    std::string str(data, data + len);
    return str;
}

// 将 string 转换为 unsigned char *
std::vector<unsigned char> string_to_uchar(const std::string& str) {
    std::vector<unsigned char> data(str.begin(), str.end());
    return data;
}


EVP_PKEY* read_key_from_file(const char* filename) {
    EVP_PKEY* pkey = NULL;
    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &pkey);
        fp = fopen(filename, "w");
        PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
        PEM_write_PUBKEY(fp, pkey);
        fclose(fp);
        EVP_PKEY_CTX_free(pctx);
    }
    else {
        pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
    }
    return pkey;
}

//std::string SM2_Sign(const unsigned char* data, size_t data_len, size_t* sig_len) {
//    // 从文件中读取密钥
//    EVP_PKEY* pkey = read_key_from_file("sm2key.pem");
//
//    // 签名
//    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
//    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, NULL);
//    EVP_DigestSignInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey);
//
//    EVP_DigestSignUpdate(md_ctx, data, data_len);
//
//    EVP_DigestSignFinal(md_ctx, NULL, sig_len);
//
//    unsigned char* sig = (unsigned char*)OPENSSL_malloc(*sig_len);
//    EVP_DigestSignFinal(md_ctx, sig, sig_len);
//
//    // 释放资源
//    EVP_MD_CTX_free(md_ctx);
//    EVP_PKEY_free(pkey);
//
//    return (uchar_to_string(sig, *sig_len));
//}

//int SM2_Verify(const unsigned char* data, size_t data_len, const unsigned char* sig, size_t sig_len) {
//    // 从文件中读取密钥
//    EVP_PKEY* pkey = read_key_from_file("sm2key.pem");
//
//    // 验签
//    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
//    EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(pkey, NULL);
//    EVP_DigestVerifyInit(md_ctx, &vctx, EVP_sm3(), NULL, pkey);
//
//    int ret = EVP_DigestVerifyUpdate(md_ctx, data, data_len);
//    ret = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
//
//    // 释放资源
//    EVP_MD_CTX_free(md_ctx);
//    EVP_PKEY_free(pkey);
//
//    return ret;
//}


std::string SM2_Sign(const std::string& data) {
    // 从文件中读取密钥
    EVP_PKEY* pkey = read_key_from_file("sm2key.pem");

    // 签名
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_DigestSignInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey);

    std::vector<unsigned char> data_uchar = string_to_uchar(data);
    EVP_DigestSignUpdate(md_ctx, data_uchar.data(), data_uchar.size());

    size_t sig_len;
    EVP_DigestSignFinal(md_ctx, NULL, &sig_len);

    unsigned char* sig = (unsigned char*)OPENSSL_malloc(sig_len);
    EVP_DigestSignFinal(md_ctx, sig, &sig_len);

    // 释放资源
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return uchar_to_string(sig, sig_len);
}



int SM2_Verify(const std::string& data, const std::string& sig) {
    // 从文件中读取密钥
    EVP_PKEY* pkey = read_key_from_file("sm2key.pem");

    // 验签
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_DigestVerifyInit(md_ctx, &vctx, EVP_sm3(), NULL, pkey);

    std::vector<unsigned char> data_uchar = string_to_uchar(data);
    int ret = EVP_DigestVerifyUpdate(md_ctx, data_uchar.data(), data_uchar.size());
    std::vector<unsigned char> sig_uchar = string_to_uchar(sig);
    ret = EVP_DigestVerifyFinal(md_ctx, sig_uchar.data(), sig_uchar.size());

    // 释放资源
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return ret;
}
