#include <string>
#include "SM2SK.h"


std::string SM3_hash(unsigned char * m, long len) {

	std::string hash;
    std::string messageInput = UCharToString(m, len);
    /*SM3*/
    unsigned char message[10000]; // 最大消息长度为 100 字节
    unsigned char digest[EVP_MAX_MD_SIZE]; // SM3 摘要长度为 32 字节


    // 将输入的字符转换为二进制消息
    int messageLen = messageInput.length();
    memcpy(message, messageInput.c_str(), messageLen);

    // 创建 SM3 上下文
    EVP_MD_CTX* SM3ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(SM3ctx);

    // 设置 SM3 哈希算法
    const EVP_MD* md = EVP_sm3();

    // 计算摘要
    EVP_DigestInit_ex(SM3ctx, md, NULL);
    EVP_DigestUpdate(SM3ctx, message, messageLen);
    EVP_DigestFinal_ex(SM3ctx, digest, NULL);

    hash = UCharToString(digest, EVP_MD_size(md));

    // 清理资源
    EVP_MD_CTX_free(SM3ctx);

	return hash;
}