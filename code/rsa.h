#ifndef _RSA_H_
#define _RSA_H_

#include "gmp.h"

#define KEY_LENGTH 2048
#define BASE 16  //输入输出的数字进制

struct triple {
    char x[KEY_LENGTH + 10];
    char y[KEY_LENGTH + 10];
    char d[KEY_LENGTH + 10];
};

struct keyPair {
    char *N;
    char *d;
    int e;
};

struct keyPair *rsaGenKey();

char *rsaEncrypt(const char *plaintext, const char *key_n, int key_e);

char *rsaDecrypt(const char *ciphertext, const char *key_n, const char *key_d);

int encode(char *in, char *buf);

int decode(char *plaintext, char *out);

#endif  // !_RSA_H_