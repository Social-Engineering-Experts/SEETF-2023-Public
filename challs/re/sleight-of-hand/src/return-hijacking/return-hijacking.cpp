/*
 * Challenge Name: sleight-of-hand
 *
 * References:
 * https://gist.github.com/rverton/a44fc8ca67ab9ec32089
 * https://blog.ret2.io/2017/11/16/dangers-of-the-decompiler/
 */

#include <iostream>
#define N 256

unsigned char magic[] = { 0xab, 0x94, 0x6, 0xfb, 0xc0, 0xb8, 0x7f, 0x85, 0xf6, 0x9e, 0xcf, 0x6b, 0x8c, 0xa6, 0xa0, 0x78, 0x75, 0x1a, 0xb9, 0x4f, 0x8f, 0x8f, 0xce, 0xed, 0x57, 0xe5, 0xfe, 0xb6, 0xc6, 0xdd, 0x77, 0x39 };
const char* key = "hithisisakey";
const char* plaintext = NULL;
unsigned char* ciphertext = NULL;

#pragma optimize( "", off )

void swap(unsigned char* a, unsigned char* b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

int KSA(const char* key, unsigned char* S) {

    int len = strlen(key);
    int j = 0;

    for (int i = 0; i < N; i++)
        S[i] = i;

    for (int i = 0; i < N; i++) {
        j = (j + S[i] + key[i % len]) % N;

        swap(&S[i], &S[j]);
    }

    return 0;
}

int PRGA(unsigned char* S, const char* plaintext, unsigned char* ciphertext) {

    int i = 0;
    int j = 0;

    for (size_t n = 0, len = strlen(plaintext); n < len; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;

        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];
        ciphertext[n] = (plaintext[n] + magic[n] - rnd) % 256;
    }
    return 0;
}

void RC4() {
    // encrypt
    unsigned char S[N];
    KSA(key, S);
    PRGA(S, plaintext, ciphertext); 
    
    // print
    printf("Ciphertext: "); // spoof hijack function as just a print function
    for (size_t i = 0, len = strlen(plaintext); i < len; i++)
        printf("%02x", ciphertext[i]); // fde5f5e12640b9860f526a9601861e752e84d866825c415549f454fe8ba3
    free(ciphertext);
    exit(0);
}

void gadget() {
    magic[0] = 110;
    magic[2] = 104;
    magic[4] = 55;
    magic[6] = 154;
    magic[8] = 105;
    magic[10] = 153;
    magic[12] = 144;
    magic[14] = 206;
    magic[16] = 161;
    magic[18] = 39;
    magic[20] = 51;
    magic[22] = 42;
    magic[24] = 151;
    magic[26] = 123;
    magic[28] = 208;
    magic[30] = 36;
    RC4();
}

void hijack() {
    int i = (int)gadget;
    __asm {
        mov ecx, [ebp-0x4] // i is [ebp-0x4]
        mov dword ptr [esp], ecx // move gadget into esp
        ret
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <plaintext>", argv[0]);
        return -1;
    }

    plaintext = argv[1];
    ciphertext = (unsigned char*)malloc(sizeof(int) * strlen(plaintext));
    hijack();
    RC4();    
}

#pragma optimize( "", on )