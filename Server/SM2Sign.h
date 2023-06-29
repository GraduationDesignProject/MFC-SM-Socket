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
//    // ��ʼ��OpenSSL��
//    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
//
//    // ����EC_KEY����
//    EC_KEY* ecKey = EC_KEY_new();
//    if (ecKey == nullptr)
//    {
//        std::cout << "Failed to create EC_KEY object." << std::endl;
//        return;
//    }
//
//    // ������Բ���߲���
//    const EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
//    if (group == nullptr)
//    {
//        std::cout << "Failed to create EC_GROUP object." << std::endl;
//        EC_KEY_free(ecKey);
//        return;
//    }
//    EC_KEY_set_group(ecKey, group);
//
//    // ������Կ��
//    if (EC_KEY_generate_key(ecKey) != 1)
//    {
//        std::cout << "Failed to generate SM2 key pair." << std::endl;
//        EC_KEY_free(ecKey);
//        EC_GROUP_free((EC_GROUP*)group);
//        return;
//    }
//
//    // ��ȡ��ǩ��������
//    size_t data_len = strlen((const char*)data);
//
//    // ����ECDSA_SIG����
//    ECDSA_SIG* signature = ECDSA_do_sign(data, data_len, ecKey);
//    if (signature == nullptr)
//    {
//        std::cout << "Failed to create ECDSA_SIG object." << std::endl;
//        EC_KEY_free(ecKey);
//        EC_GROUP_free((EC_GROUP*)group);
//        return;
//    }
//
//    // ���л�ǩ��
//    unsigned char* der_signature = NULL;
//    int der_signature_len = i2d_ECDSA_SIG(signature, &der_signature);
//
//    // ������л����ǩ��
//    std::cout << "Serialized Signature: ";
//    //for (int i = 0; i < der_signature_len; i++)
//    //{
//    //    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(der_signature[i]);
//    //}
//    //std::cout << std::endl;
//    // 
//    // ������Դ
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
//    // ��֤ǩ��
//    int verification_result = ECDSA_do_verify(data, data_len, signature, ecKey);
//
//    // �����֤���
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
//    // ������Դ
//    EC_KEY_free(ecKey);
//    EC_GROUP_free((EC_GROUP*)group);
//
//
//    // ����OpenSSL��
//}



std::string uchar_to_string(const unsigned char* data, size_t len) {
    std::string str(data, data + len);
    return str;
}

// �� string ת��Ϊ unsigned char *
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
//    // ���ļ��ж�ȡ��Կ
//    EVP_PKEY* pkey = read_key_from_file("sm2key.pem");
//
//    // ǩ��
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
//    // �ͷ���Դ
//    EVP_MD_CTX_free(md_ctx);
//    EVP_PKEY_free(pkey);
//
//    return (uchar_to_string(sig, *sig_len));
//}

//int SM2_Verify(const unsigned char* data, size_t data_len, const unsigned char* sig, size_t sig_len) {
//    // ���ļ��ж�ȡ��Կ
//    EVP_PKEY* pkey = read_key_from_file("sm2key.pem");
//
//    // ��ǩ
//    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
//    EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(pkey, NULL);
//    EVP_DigestVerifyInit(md_ctx, &vctx, EVP_sm3(), NULL, pkey);
//
//    int ret = EVP_DigestVerifyUpdate(md_ctx, data, data_len);
//    ret = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
//
//    // �ͷ���Դ
//    EVP_MD_CTX_free(md_ctx);
//    EVP_PKEY_free(pkey);
//
//    return ret;
//}


std::string SM2_Sign(const std::string& data) {
    // ���ļ��ж�ȡ��Կ
    EVP_PKEY* pkey = read_key_from_file("sm2key.pem");

    // ǩ��
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_DigestSignInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey);

    std::vector<unsigned char> data_uchar = string_to_uchar(data);
    EVP_DigestSignUpdate(md_ctx, data_uchar.data(), data_uchar.size());

    size_t sig_len;
    EVP_DigestSignFinal(md_ctx, NULL, &sig_len);

    unsigned char* sig = (unsigned char*)OPENSSL_malloc(sig_len);
    EVP_DigestSignFinal(md_ctx, sig, &sig_len);

    // �ͷ���Դ
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return uchar_to_string(sig, sig_len);
}



int SM2_Verify(const std::string& data, const std::string& sig) {
    // ���ļ��ж�ȡ��Կ
    EVP_PKEY* pkey = read_key_from_file("sm2key.pem");

    // ��ǩ
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_DigestVerifyInit(md_ctx, &vctx, EVP_sm3(), NULL, pkey);

    std::vector<unsigned char> data_uchar = string_to_uchar(data);
    int ret = EVP_DigestVerifyUpdate(md_ctx, data_uchar.data(), data_uchar.size());
    std::vector<unsigned char> sig_uchar = string_to_uchar(sig);
    ret = EVP_DigestVerifyFinal(md_ctx, sig_uchar.data(), sig_uchar.size());

    // �ͷ���Դ
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return ret;
}
