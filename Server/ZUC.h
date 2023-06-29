//#pragma once
///*ZUC*/
//
//#include <iostream>
//#include <cstdint>
//#include <cstring>
//
//// ZUC 初始化函数
//void ZUCInitialization(uint32_t* LFSR, uint32_t* LFSR_1, uint32_t* LFSR_2, uint32_t* LFSR_3, uint32_t* R1, uint32_t* R2, uint32_t* R3);
//void ZUCGenerateKeyStream(uint32_t* LFSR, uint32_t* LFSR_1, uint32_t* LFSR_2, uint32_t* LFSR_3, uint32_t* R1, uint32_t* R2, uint32_t* R3);
//void ZUCShift(uint32_t* LFSR, uint32_t* LFSR_1, uint32_t* LFSR_2, uint32_t* LFSR_3);
//
//// ZUC 加解密函数
//void ZUCEncryptDecrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input, uint8_t* output, int length);
//
//// ZUC 初始化函数
//void ZUCInitialization(uint32_t* LFSR, uint32_t* LFSR_1, uint32_t* LFSR_2, uint32_t* LFSR_3, uint32_t* R1, uint32_t* R2, uint32_t* R3)
//{
//    *LFSR = 0x87654321;
//    *LFSR_1 = 0x87654321;
//    *LFSR_2 = 0x87654321;
//    *LFSR_3 = 0x87654321;
//    *R1 = 0;
//    *R2 = 0;
//    *R3 = 0;
//
//    for (int i = 0; i < 32; i++)
//    {
//        ZUCGenerateKeyStream(LFSR, LFSR_1, LFSR_2, LFSR_3, R1, R2, R3);
//    }
//}
//
//// ZUC 移位函数
//void ZUCShift(uint32_t* LFSR, uint32_t* LFSR_1, uint32_t* LFSR_2, uint32_t* LFSR_3)
//{
//    uint32_t b0 = ((*LFSR << 8) ^ (*LFSR)) & 0x000000FF;
//    uint32_t b1 = ((*LFSR_1 << 19) ^ (*LFSR_1)) & 0xFFFFFFFF;
//    uint32_t b2 = ((*LFSR_2 << 13) ^ (*LFSR_2)) & 0xFFFFFFFF;
//    uint32_t b3 = ((*LFSR_3 << 2) ^ (*LFSR_3)) & 0xFFFFFFFF;
//
//    *LFSR = (*LFSR >> 8) | (b1 << 24);
//    *LFSR_1 = (*LFSR_1 >> 19) | (b2 << 13);
//    *LFSR_2 = (*LFSR_2 >> 13) | (b3 << 19);
//    *LFSR_3 = (*LFSR_3 >> 2) | (b0 << 30);
//}
//
//// ZUC 生成密钥流
//void ZUCGenerateKeyStream(uint32_t* LFSR, uint32_t* LFSR_1, uint32_t* LFSR_2, uint32_t* LFSR_3, uint32_t* R1, uint32_t* R2, uint32_t* R3)
//{
//    uint32_t F_R1 = ((*R1 & 0x000000FF) + (*R2 & 0x000000FF) + (*R3 & 0x000000FF)) & 0x000000FF;
//    uint32_t F_R2 = (((*R1 >> 8) & 0x000000FF) + ((*R2 >> 8) & 0x000000FF) + ((*R3 >> 8) & 0x000000FF)) & 0x000000FF;
//    uint32_t F_R3 = (((*R1 >> 16) & 0x000000FF) + ((*R2 >> 16) & 0x000000FF) + ((*R3 >> 16) & 0x000000FF)) & 0x000000FF;
//    uint32_t F_R4 = (((*R1 >> 24) & 0x000000FF) + ((*R2 >> 24) & 0x000000FF) + ((*R3 >> 24) & 0x000000FF)) & 0x000000FF;
//
//    uint32_t u = F_R1 + F_R2 + F_R3 + F_R4;
//
//    ZUCShift(LFSR, LFSR_1, LFSR_2, LFSR_3);
//
//    uint32_t S = (*LFSR & 0x000001FF) ^ (*LFSR_1 & 0x000001FF) ^ (*LFSR_2 & 0x000001FF) ^ (*LFSR_3 & 0x000001FF);
//
//    uint32_t x = u ^ S;
//
//    *R1 = ((x << 24) | (*R1 >> 8)) & 0xFFFFFFFF;
//    *R2 = ((*R1 << 8) | (*R2 >> 24)) & 0xFFFFFFFF;
//    *R3 = ((*R2 << 8) | (*R3 >> 24)) & 0xFFFFFFFF;
//}
//
//// ZUC 加解密函数
//void ZUCEncryptDecrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input, uint8_t* output, int length)
//{
//    uint32_t LFSR, LFSR_1, LFSR_2, LFSR_3, R1, R2, R3;
//    uint8_t keystream_byte;
//    uint32_t keystream;
//
//    ZUCInitialization(&LFSR, &LFSR_1, &LFSR_2, &LFSR_3, &R1, &R2, &R3);
//
//    for (int i = 0; i < length; i++)
//    {
//        if (i % 4 == 0)
//        {
//            ZUCGenerateKeyStream(&LFSR, &LFSR_1, &LFSR_2, &LFSR_3, &R1, &R2, &R3);
//            keystream = R1;
//        }
//
//        keystream_byte = (keystream >> ((i % 4) * 8)) & 0xFF;
//        output[i] = input[i] ^ keystream_byte;
//    }
//}






#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>

const unsigned int ZUC_KEY_LEN = 16;  // 密钥长度为16字节
const unsigned int ZUC_IV_LEN = 16;   // 初始化向量长度为16字节
const unsigned int ZUC_DATA_LEN = 100; // 加解密数据的最大长度为100字节

const unsigned int LFSR_S0_INIT = 0x96D9D7D5;
const unsigned int LFSR_S1_INIT = 0xD6AD8D9D;
const unsigned int LFSR_S2_INIT = 0x8A84E681;
const unsigned int LFSR_S3_INIT = 0xE378F5A3;
const unsigned int LFSR_S4_INIT = 0x0707DDB4;
const unsigned int LFSR_S5_INIT = 0xD2DCCA0B;
const unsigned int LFSR_S6_INIT = 0xBFA4F1E6;
const unsigned int LFSR_S7_INIT = 0x797762C2;

const unsigned int LFSR_BIT_MASK = 0x1u;

const unsigned int ZUC_SBOX[8][16] = {
    {0x4, 0xD, 0x3, 0x8, 0x1, 0xA, 0xF, 0x2, 0xE, 0xC, 0xB, 0x7, 0x6, 0x0, 0x9, 0x5},
    {0xF, 0x1, 0xC, 0x8, 0x2, 0x6, 0x0, 0xD, 0x3, 0x4, 0x9, 0x7, 0x5, 0xB, 0xE, 0xA},
    {0x0, 0xE, 0x7, 0xB, 0xA, 0x4, 0xD, 0x1, 0x3, 0xC, 0x9, 0x5, 0x8, 0x2, 0xF, 0x6},
    {0xD, 0x8, 0xB, 0x5, 0x6, 0xF, 0x0, 0x9, 0xC, 0x7, 0x2, 0x4, 0xA, 0xE, 0x1, 0x3},
    {0x8, 0xF, 0x6, 0xB, 0x1, 0x3, 0x4, 0xA, 0xD, 0x7, 0x2, 0x9, 0x0, 0xC, 0x5, 0xE},
    {0xB, 0x5, 0x0, 0xE, 0xC, 0x9, 0xF, 0xA, 0x2, 0x3, 0x7, 0x8, 0x4, 0x6, 0x1, 0xD},
    {0xF, 0x4, 0x6, 0xC, 0xB, 0xE, 0x2, 0x0, 0xD, 0x1, 0xA, 0x7, 0x5, 0x9, 0x3, 0x8},
    {0x9, 0x3, 0x7, 0xB, 0xF, 0x1, 0x6, 0x0, 0x8, 0xE, 0x5, 0xD, 0x4, 0xA, 0xC, 0x2}
};

struct LFSR {
    unsigned int LFSR_S0;
    unsigned int LFSR_S1;
    unsigned int LFSR_S2;
    unsigned int LFSR_S3;
    unsigned int LFSR_S4;
    unsigned int LFSR_S5;
    unsigned int LFSR_S6;
    unsigned int LFSR_S7;
};

void ZUC_Initialization(const unsigned char* key, const unsigned char* iv, LFSR& lfsr);
void ZUC_GenerateKeystream(const unsigned char* data, unsigned int len, unsigned char* keystream, LFSR& lfsr);


void ZUC_Initialization(const unsigned char* key, const unsigned char* iv, LFSR& lfsr) {
    // 初始化 LFSR 寄存器状态
    lfsr.LFSR_S0 = LFSR_S0_INIT;
    lfsr.LFSR_S1 = LFSR_S1_INIT;
    lfsr.LFSR_S2 = LFSR_S2_INIT;
    lfsr.LFSR_S3 = LFSR_S3_INIT;
    lfsr.LFSR_S4 = LFSR_S4_INIT;
    lfsr.LFSR_S5 = LFSR_S5_INIT;
    lfsr.LFSR_S6 = LFSR_S6_INIT;
    lfsr.LFSR_S7 = LFSR_S7_INIT;

    // 按字节异或密钥
    for (unsigned int i = 0; i < ZUC_KEY_LEN; i++) {
        lfsr.LFSR_S0 ^= key[i];
        lfsr.LFSR_S1 ^= key[i];
        lfsr.LFSR_S2 ^= key[i];
        lfsr.LFSR_S3 ^= key[i];
        lfsr.LFSR_S4 ^= key[i];
        lfsr.LFSR_S5 ^= key[i];
        lfsr.LFSR_S6 ^= key[i];
        lfsr.LFSR_S7 ^= key[i];
    }

    // 按字节异或初始化向量
    for (unsigned int i = 0; i < ZUC_IV_LEN; i++) {
        lfsr.LFSR_S0 ^= iv[i];
        lfsr.LFSR_S1 ^= iv[i];
        lfsr.LFSR_S2 ^= iv[i];
        lfsr.LFSR_S3 ^= iv[i];
        lfsr.LFSR_S4 ^= iv[i];
        lfsr.LFSR_S5 ^= iv[i];
        lfsr.LFSR_S6 ^= iv[i];
        lfsr.LFSR_S7 ^= iv[i];
    }

    // 执行 32 次初始化操作
    for (int i = 0; i < 32; i++) {
        unsigned int t1 = (lfsr.LFSR_S0 << 15) ^ (lfsr.LFSR_S0 >> 17) ^ (lfsr.LFSR_S0 << 23);
        unsigned int t2 = (lfsr.LFSR_S1 << 3) ^ (lfsr.LFSR_S1 >> 29) ^ (lfsr.LFSR_S1 << 8);
        unsigned int t3 = (lfsr.LFSR_S2 << 7) ^ (lfsr.LFSR_S2 >> 25) ^ (lfsr.LFSR_S2 << 13);
        unsigned int t4 = (lfsr.LFSR_S3 << 2) ^ (lfsr.LFSR_S3 >> 30) ^ (lfsr.LFSR_S3 << 15);
        unsigned int t5 = (lfsr.LFSR_S4 << 3) ^ (lfsr.LFSR_S4 >> 29);
        unsigned int t6 = (lfsr.LFSR_S5 << 7) ^ (lfsr.LFSR_S5 >> 25);
        unsigned int t7 = (lfsr.LFSR_S6 << 13) ^ (lfsr.LFSR_S6 >> 19);
        unsigned int t8 = (lfsr.LFSR_S7 << 2) ^ (lfsr.LFSR_S7 >> 30);

        lfsr.LFSR_S0 = lfsr.LFSR_S1;
        lfsr.LFSR_S1 = lfsr.LFSR_S2;
        lfsr.LFSR_S2 = lfsr.LFSR_S3;
        lfsr.LFSR_S3 = lfsr.LFSR_S4;
        lfsr.LFSR_S4 = lfsr.LFSR_S5;
        lfsr.LFSR_S5 = lfsr.LFSR_S6;
        lfsr.LFSR_S6 = lfsr.LFSR_S7;
        lfsr.LFSR_S7 = t1 ^ t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7 ^ t8;
    }
}

void ZUC_GenerateKeystream(const unsigned char* data, unsigned int len, unsigned char* keystream, LFSR& lfsr) {
    for (unsigned int i = 0; i < len; i++) {
        unsigned char f = static_cast<unsigned char>(lfsr.LFSR_S0 ^ (lfsr.LFSR_S0 >> 9) ^ (lfsr.LFSR_S1 << 6) ^
            (lfsr.LFSR_S1 >> 9) ^ (lfsr.LFSR_S2 << 3) ^
            (lfsr.LFSR_S2 >> 29) ^ (lfsr.LFSR_S3 << 2) ^
            (lfsr.LFSR_S3 >> 29) ^ (lfsr.LFSR_S4 << 3) ^
            (lfsr.LFSR_S4 >> 28) ^ (lfsr.LFSR_S5 >> 31) ^
            (lfsr.LFSR_S6 << 6) ^ (lfsr.LFSR_S6 >> 27) ^
            (lfsr.LFSR_S7 >> 31));

        unsigned int t1 = (lfsr.LFSR_S0 << 15) ^ (lfsr.LFSR_S0 >> 17) ^ (lfsr.LFSR_S0 << 23);
        unsigned int t2 = (lfsr.LFSR_S1 << 3) ^ (lfsr.LFSR_S1 >> 29) ^ (lfsr.LFSR_S1 << 8);
        unsigned int t3 = (lfsr.LFSR_S2 << 7) ^ (lfsr.LFSR_S2 >> 25) ^ (lfsr.LFSR_S2 << 13);
        unsigned int t4 = (lfsr.LFSR_S3 << 2) ^ (lfsr.LFSR_S3 >> 30) ^ (lfsr.LFSR_S3 << 15);
        unsigned int t5 = (lfsr.LFSR_S4 << 3) ^ (lfsr.LFSR_S4 >> 29);
        unsigned int t6 = (lfsr.LFSR_S5 << 7) ^ (lfsr.LFSR_S5 >> 25);
        unsigned int t7 = (lfsr.LFSR_S6 << 13) ^ (lfsr.LFSR_S6 >> 19);
        unsigned int t8 = (lfsr.LFSR_S7 << 2) ^ (lfsr.LFSR_S7 >> 30);

        unsigned char b0 = static_cast<unsigned char>((f + lfsr.LFSR_S0 + t1) & 0xFF);
        unsigned char b1 = static_cast<unsigned char>((f + lfsr.LFSR_S1 + t2) & 0xFF);
        unsigned char b2 = static_cast<unsigned char>((f + lfsr.LFSR_S2 + t3) & 0xFF);
        unsigned char b3 = static_cast<unsigned char>((f + lfsr.LFSR_S3 + t4) & 0xFF);
        unsigned char b4 = static_cast<unsigned char>((f + lfsr.LFSR_S4 + t5) & 0xFF);
        unsigned char b5 = static_cast<unsigned char>((f + lfsr.LFSR_S5 + t6) & 0xFF);
        unsigned char b6 = static_cast<unsigned char>((f + lfsr.LFSR_S6 + t7) & 0xFF);
        unsigned char b7 = static_cast<unsigned char>((f + lfsr.LFSR_S7 + t8) & 0xFF);

        unsigned int u = static_cast<unsigned int>(b0) |
            (static_cast<unsigned int>(b1) << 8) |
            (static_cast<unsigned int>(b2) << 16) |
            (static_cast<unsigned int>(b3) << 24);
        unsigned int v = static_cast<unsigned int>(b4) |
            (static_cast<unsigned int>(b5) << 8) |
            (static_cast<unsigned int>(b6) << 16) |
            (static_cast<unsigned int>(b7) << 24);

        keystream[i] = static_cast<unsigned char>(data[i] ^ (u ^ v));

        unsigned int s0_out = ((lfsr.LFSR_S0 << 8) ^ ZUC_SBOX[0][(lfsr.LFSR_S0 >> 24)]) & LFSR_BIT_MASK;
        unsigned int s1_out = ((lfsr.LFSR_S1 << 8) ^ ZUC_SBOX[1][(lfsr.LFSR_S1 >> 24)]) & LFSR_BIT_MASK;
        unsigned int s2_out = ((lfsr.LFSR_S2 << 8) ^ ZUC_SBOX[2][(lfsr.LFSR_S2 >> 24)]) & LFSR_BIT_MASK;
        unsigned int s3_out = ((lfsr.LFSR_S3 << 8) ^ ZUC_SBOX[3][(lfsr.LFSR_S3 >> 24)]) & LFSR_BIT_MASK;
        unsigned int s4_out = ((lfsr.LFSR_S4 << 8) ^ ZUC_SBOX[4][(lfsr.LFSR_S4 >> 24)]) & LFSR_BIT_MASK;
        unsigned int s5_out = ((lfsr.LFSR_S5 << 8) ^ ZUC_SBOX[5][(lfsr.LFSR_S5 >> 24)]) & LFSR_BIT_MASK;
        unsigned int s6_out = ((lfsr.LFSR_S6 << 8) ^ ZUC_SBOX[6][(lfsr.LFSR_S6 >> 24)]) & LFSR_BIT_MASK;
        unsigned int s7_out = ((lfsr.LFSR_S7 << 8) ^ ZUC_SBOX[7][(lfsr.LFSR_S7 >> 24)]) & LFSR_BIT_MASK;

        lfsr.LFSR_S0 = s0_out | ((lfsr.LFSR_S0 >> 1) & 0x7FFFFFFF);
        lfsr.LFSR_S1 = s1_out | ((lfsr.LFSR_S1 >> 1) & 0x7FFFFFFF);
        lfsr.LFSR_S2 = s2_out | ((lfsr.LFSR_S2 >> 1) & 0x7FFFFFFF);
        lfsr.LFSR_S3 = s3_out | ((lfsr.LFSR_S3 >> 1) & 0x7FFFFFFF);
        lfsr.LFSR_S4 = s4_out | ((lfsr.LFSR_S4 >> 1) & 0x7FFFFFFF);
        lfsr.LFSR_S5 = s5_out | ((lfsr.LFSR_S5 >> 1) & 0x7FFFFFFF);
        lfsr.LFSR_S6 = s6_out | ((lfsr.LFSR_S6 >> 1) & 0x7FFFFFFF);
        lfsr.LFSR_S7 = s7_out | ((lfsr.LFSR_S7 >> 1) & 0x7FFFFFFF);
    }
}