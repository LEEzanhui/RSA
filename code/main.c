/*
linux
g++ -c rsa.c -o rsa.o -lgmp
g++ -c main.c -o main.o -lgmp
g++ rsa.o main.o -o main -lgmp
./main
*/

#include "gmp.h"
#include "rsa.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

int main(int argc, char const* argv[]) {
    struct keyPair* p = rsaGenKey();

    printf("N = 0x%s\n\n", p->N);
    printf("d = 0x%s\n\n", p->d);
    printf("e = 0x%x\n\n", p->e);

    char buf[KEY_LENGTH + 10];
    char in[KEY_LENGTH + 10];

    // 整行输入
    printf("input: ");
    scanf("%[^\n]", buf);
    getchar();

    int error = encode(in, buf);
    if (error == 1) {
        return 0;
    }

    char* ciphertext = rsaEncrypt(in, p->N, p->e);
    printf("\nciphertext: 0x%s\n\n", ciphertext);

    char* out = rsaDecrypt(ciphertext, p->N, p->d);

    char plaintext[KEY_LENGTH + 10];
    error = decode(plaintext, out);
    if (error == 1) {
        return 0;
    }

    printf("plaintext: %s\n\n", plaintext);

    free(ciphertext);
    free(out);

    return 0;
}
