#include <string>
#include "SM2SK.h"


std::string SM3_hash(unsigned char * m, long len) {

	std::string hash;
    std::string messageInput = UCharToString(m, len);
    /*SM3*/
    unsigned char message[10000]; // �����Ϣ����Ϊ 100 �ֽ�
    unsigned char digest[EVP_MAX_MD_SIZE]; // SM3 ժҪ����Ϊ 32 �ֽ�


    // ��������ַ�ת��Ϊ��������Ϣ
    int messageLen = messageInput.length();
    memcpy(message, messageInput.c_str(), messageLen);

    // ���� SM3 ������
    EVP_MD_CTX* SM3ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(SM3ctx);

    // ���� SM3 ��ϣ�㷨
    const EVP_MD* md = EVP_sm3();

    // ����ժҪ
    EVP_DigestInit_ex(SM3ctx, md, NULL);
    EVP_DigestUpdate(SM3ctx, message, messageLen);
    EVP_DigestFinal_ex(SM3ctx, digest, NULL);

    hash = UCharToString(digest, EVP_MD_size(md));

    // ������Դ
    EVP_MD_CTX_free(SM3ctx);

	return hash;
}