#include "rsa.h"

#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct triple extEuclid(char* a, char* b) {
    char x[KEY_LENGTH + 10];
    char y[KEY_LENGTH + 10];
    char d[KEY_LENGTH + 10];
    struct triple ee;
    ee.x[0] = '1';
    ee.x[1] = '\0';
    ee.y[0] = '0';
    ee.y[1] = '\0';
    strcpy(ee.d, a);
    if (strcmp(b, "0") == 0) {
        return ee;
    }

    mpz_t amb, ma, mb;
    mpz_init(amb);
    mpz_init_set_str(ma, a, BASE);
    mpz_init_set_str(mb, b, BASE);
    mpz_mod(amb, ma, mb);
    char mid[KEY_LENGTH + 10];
    mpz_get_str(mid, BASE, amb);

    ee = extEuclid(b, mid);
    strcpy(x, ee.y);

    mpz_div(ma, ma, mb);
    mpz_t ex, ey, my;
    mpz_init(my);
    mpz_init_set_str(ex, ee.x, BASE);
    mpz_init_set_str(ey, ee.y, BASE);
    mpz_mul(ma, ma, ey);

    mpz_sub(my, ex, ma);
    char temp[KEY_LENGTH + 10];
    mpz_get_str(temp, BASE, my);
    // y = ee.x - (a / b) * ee.y;

    struct triple ref;
    strcpy(ref.x, x);
    strcpy(ref.y, temp);
    strcpy(ref.d, ee.d);

    mpz_clear(amb);
    mpz_clear(ma);
    mpz_clear(mb);
    mpz_clear(ex);
    mpz_clear(ey);
    mpz_clear(my);
    return ref;
}

// 生成两个大素数
mpz_t* rsaGenPrime() {
    // 随机数
    gmp_randstate_t grt;
    gmp_randinit_default(grt);
    gmp_randseed_ui(grt, time(NULL));

    mpz_t p, q;
    mpz_init(p);
    mpz_init(q);

    // 随机生成大整数
    mpz_urandomb(p, grt, KEY_LENGTH / 2);
    mpz_urandomb(q, grt, KEY_LENGTH / 2);

    mpz_t* ref = (mpz_t*)malloc(sizeof(mpz_t) * 2);
    mpz_init(ref[0]);
    mpz_init(ref[1]);

    // 使用GMP自带的素数生成函数
    mpz_nextprime(ref[0], p);
    mpz_nextprime(ref[1], q);

    gmp_printf("p = 0x%ZX\n\n", p);
    gmp_printf("q = 0x%ZX\n\n", q);

    mpz_clear(p);
    mpz_clear(q);

    return ref;
}

// 生成密钥对
struct keyPair* rsaGenKey() {
    mpz_t* PandQ = rsaGenPrime();

    mpz_t N, e, phiN;
    mpz_init(N);
    mpz_init(phiN);
    // 设置e为65537
    mpz_init_set_ui(e, 65537);

    // 计算n=p*q
    mpz_mul(N, PandQ[0], PandQ[1]);

    // 计算欧拉函数φ(N)=(p-1)*(q-1)
    mpz_sub_ui(PandQ[0], PandQ[0], 1);
    mpz_sub_ui(PandQ[1], PandQ[1], 1);
    mpz_mul(phiN, PandQ[0], PandQ[1]);

    // 计算数论倒数
    mpz_t d;
    mpz_init(d);
    // mpz_invert(d, e, phiN);
    char ce[KEY_LENGTH + 10];
    char cphiN[KEY_LENGTH + 10];
    mpz_get_str(ce, BASE, e);
    mpz_get_str(cphiN, BASE, phiN);
    struct triple ee = extEuclid(cphiN, ce);
    mpz_set_str(d, ee.y, BASE);

    mpz_t ze;
    mpz_init(ze);
    for (; mpz_cmp(d, ze) < 0; mpz_add(d, d, phiN)) {
    }

    struct keyPair* ref = (struct keyPair*)malloc(sizeof(struct keyPair));

    char* buf_n = (char*)malloc(sizeof(char) * (KEY_LENGTH + 10));
    char* buf_d = (char*)malloc(sizeof(char) * (KEY_LENGTH + 10));

    mpz_get_str(buf_n, BASE, N);
    ref->N = buf_n;
    mpz_get_str(buf_d, BASE, d);
    ref->d = buf_d;
    ref->e = 65537;

    mpz_clear(PandQ[0]);
    mpz_clear(PandQ[1]);
    mpz_clear(N);
    mpz_clear(d);
    mpz_clear(e);
    mpz_clear(phiN);
    free(PandQ);

    return ref;
}

// 加密函数
char* rsaEncrypt(const char* plaintext, const char* key_n, int key_e) {
    mpz_t M, C, N;
    mpz_init_set_str(M, plaintext, BASE);
    mpz_init_set_str(N, key_n, BASE);
    mpz_init_set_ui(C, 0);

    mpz_powm_ui(C, M, key_e, N);  //使用GMP中模幂计算函数

    char* ref = (char*)malloc(sizeof(char) * (KEY_LENGTH + 10));
    mpz_get_str(ref, BASE, C);

    return ref;
}

// 解密函数
char* rsaDecrypt(const char* ciphertext, const char* key_n, const char* key_d) {
    mpz_t M, C, N, d;
    mpz_init_set_str(C, ciphertext, BASE);
    mpz_init_set_str(N, key_n, BASE);
    mpz_init_set_str(d, key_d, BASE);
    mpz_init(M);

    // 模幂计算
    mpz_powm(M, C, d, N);

    char* ref = (char*)malloc(sizeof(char) * (KEY_LENGTH + 10));
    mpz_get_str(ref, BASE, M);

    return ref;
}

void linkInt(char* ch, int num) {
    int temp = num;
    char mid[2];
    mid[0] = '0' + temp;
    mid[1] = '\0';
    strcat(ch, mid);
}

int encode(char* in, char* buf) {
    if (strlen(buf) > (KEY_LENGTH / 4 - 9 - 3 * 8) / 3) {
        printf("error: message too long\n");
        return 1;
    }

    in[0] = '1';
    in[1] = '\0';

    strcat(in, "00");
    strcat(in, "002");

    for (int i = 0; i < KEY_LENGTH / 4 - strlen(buf) * 4 - 9; i++) {
        linkInt(in, (rand() % 9 + 1));
    }
    strcat(in, "000");

    char add[KEY_LENGTH + 10];
    add[0] = '\0';
    for (int i = 0; buf[i] != '\0'; i++) {
        int temp = (int)buf[i];
        char mid[4];
        mid[0] = '0' + temp / 100;
        mid[1] = '0' + (temp % 100) / 10;
        mid[2] = '0' + (temp % 10);
        mid[3] = '\0';
        strcat(add, mid);
    }

    strcat(in, add);

    return 0;
}

int decode(char* plaintext, char* out) {
    plaintext[0] = '\0';
    int i = 0;
    for (i = 6; out[i] != '0'; i++) {
    }
    i += 3;

    for (; out[i] != '\0'; i += 3) {
        int temp = 0;
        for (int j = 0; j < 3; j++) {
            temp *= 10;
            temp += (int)(out[i + j] - '0');
        }
        char mid[2];
        mid[0] = (char)(temp);
        mid[1] = '\0';
        strcat(plaintext, mid);
    }

    return 0;
}