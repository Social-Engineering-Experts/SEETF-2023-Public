#include <iostream>
#include <stdio.h>
#include <cstring>
#define LEN 1030

char n[LEN] = "780c9276bf474a488e56d5ec3a4827b8cffeca20cfb3dc5f53b25bc6b4d61152de663e13613222d8b1425a4e3329ac9b302586a0a097e74058466d070fba734ceedde9ef151611e937f249cb4f70e303efc2a96a0b586757a2bb517019aecc9a2cf2bbf6ffc0b496276a2366d2d0131d2829829a100a37e0da3a755aa6ab372430a3c0a666a7a502098a98315684a1c92c53cbafe3d4fbedfc671e1265fbd668c7f399a2371f0c2ad0b16c56ee0478290c34da9cbb8ba6bfc1409c57f5ef1cfaa7517cfe02674479f2f4ec5d1d090f1efa3b04a9d9df178a94c277d8b32a6bf030efe2a7e746c055684bc308c8e5776f0fdf88b52155c149b6810cade8c52f83998f111c773e91e887ce5b2ef1db10ecbc3a5e4aca6a75d426d7334799ebd7cd688fc75de08f7555e791b5e8634a7cdbb1e118ea2e61e287b332f00cf4cafff1b2fa7484aa2eebfb785df0e39dcac7bddb2a085d7bc845c52489202cb48b0e5efcd1ff538df61b6f93578858316fc51be6e5e0eb77fab23b5f94afca48a817f94145c3e66f62a8852e8cbc5de197cf03a7ebf20c6137d9404260b1600e913c946a987d9fd25d98dffc7d0f2b534cee3482789d06191fa10133fda862337cf4e000586f188bcab5d05b8e40726040e7c5aa762b789ed09ff5c0faf39e9e18821cd020f1ca7b16a993219a2172a1af5a78b798ae1522f2f6bfc6657db3b6620a69";
char c[LEN] = "72feecd39ab2b416966c16b6cfa3b55ce50ffa5d02dbca44d56377be2d8f00e8f8df5548651b1ea37ffe37b9937a0673b1d5756f057625f76c82a6e9daa180baaef543e3bac57c95326e65315831d76b766d354495a2e233d76bfe80b404c0d254ecdc4107704966d1cd959bb26802a7d505250710047497b5dfde45bd9164700d5d3dfa40900fbaa02ae1a047eaac262d1069211fe0b39d86516dde1fe3144120bcbecf6a0c8a50d068cff5b55a1187765bfefc288f5c511ff217c2f435f2ff4524b513d8625aa87239f287423febb8ada47b0f6aaeac71be7355b4e9b12c20de815a052108edc78325b3b3a993ee4612efd17a30626d375f0669adb2632222c5a922cef0a515d848877b2f440f38b3554decd8fda0327995df2a64a426088389495caf89a540a69d2c048d46a29d9d90a560deb1859898398d46a3fe8070d07a34e1da5f8108c2f0a1012e76f422c09a6847cf9b16653c77bca3e3939e14dc01a2757b32ff0ccf0ab62d28c8266c8e1f47e7e25a444e48ffd4f0288e158a9404947786a11e869b6fdc3204b9fc433ba28ac77775ff4b51b1df668154d32e30b01a0ff5968f9bb7b4f5bc772ffc4b1c5af1859dae67552e077f650842c60f4fe1929468f5a701b66bdd9d01c1ce22496c49091f225a26987e3e0f2d7a7f27ab20fd3448450794835477786f6b9a97bf4d4091c9b261d75d62120138b3104f76";
char d[LEN] = "e7787d3f8c184210c0f99dc6ea823ab6334e2d9ae8acaa00d94eed4ef44e68ad76343fea24e2ccfb4ae358a7101e85ae23a3df24149748677b4f7b062a55ad726539dd51844efda612c38edd194d6c6b5117b569bce7a9cbc4b4bc3f73eab892b1795ca60e485aebe900fcdef242c2344d407e9d06b05e77db8c27c37552bd902a4a520f79f3e1a5e9fd3f182f5e16e117bbdbfe3225a45ce956181cc16f166a58abcbe345543709d1703acc8a27d9eaadcf1d67544ce45ce83985d1c5e45cc3a89f46faa80876f906aa444b7a520a9f1d1eec068c559b35b92f062cbae2e5bcc279c3ff93460ea04649696067854b3dd699e92992a8b883e0f4d291bbe79417d5defe75baa3c9de6cef7279d4cb19d1f40eedf90928165f3d4be915e206cdeb732f1fda3c3fd88ca089719cb3ef38c6040602625e466765c47637185605bece27a0640f42d29e78aa233735402c795b8401b70e72fae7e9bb24696b41844e24f3b197a277cf603aa25127028023de12044efa4b020202e2acdb5612e990556599d4c0f9fc37404dcf5d4ab07dc4ba8b0d0e03420a08db3e0a85faa77d2538ba11f64269e7ae049cc83e45780c0ed9f7c101dcf8dac55b5edc04a00a806f496beee6f33680eab37da22061573f8c933226b1a8e3af754ceba20c42786e78a6a30c19e46f5a7e12ce989a67ab84c79a8f3c571e32af64d031bf3b2c65538b4a19";

bool ge(char* a, char* b) {
    int a_len = (int)strlen(a);
    int b_len = (int)strlen(b);
    if (b_len > a_len) {
        return false;
    }
    if (a_len > b_len) {
        return true;
    }
    for (int ptr = a_len - 1; ptr >= 0; ptr -= 1) {
        if (b[ptr] > a[ptr]) {
            return false;
        }
        if (a[ptr] > b[ptr]) {
            return true;
        }
    }
    return true;
}

int getDigit(char a) {
    if (!a) return 0;
    if (a >= 'a') return a - 'W';
    return a - '0';
}

char getChar(int a) {
    if (a >= 10) return a + 'W';
    return a + '0';
}

void flip(char* a) {
    int ptr = 0;
    while (a[ptr]) {
        int tmp = getDigit(a[ptr]);
        a[ptr] = getChar(15 - tmp);
        ptr++;
    }
}

void removeZeroes(char* a) {
    int tmp = strlen(a);
    while (tmp > 0) {
        if (a[tmp] == '0' || a[tmp] == '\0') {
            a[tmp] = '\0';
            tmp -= 1;
        }
        else break;
    }
}

void sub(char* a, char* b) {
    int ptr = 0;
    int ptr0;
    int ad, bd;
    while (a[ptr]) {
        ad = getDigit(a[ptr]);
        bd = getDigit(b[ptr]);
        if (ad < bd) {
            ad += 16;
            ptr0 = ptr;
            while (1) {
                ptr0++;
                if (getDigit(a[ptr0])) {
                    a[ptr0] = getChar(getDigit(a[ptr0]) - 1);
                    break;
                }
                else a[ptr0] = 'f';
            }
        }
        a[ptr] = getChar(ad - bd);
        ptr++;
    }
    removeZeroes(a);
}

void shr(char* a, int offset) {
    for (int j = 0; j < offset; j++) {
        for (int ptr = LEN - 2; ptr > 0; ptr--) {
            a[ptr] = a[ptr - 1];
        }
        a[0] = '0';
        removeZeroes(a);
        int cnt = 0;
        while (ge(a, n)) {
            cnt++;
            sub(a, n);
        }
    }
}

void add(char* a, char* b) {
    int a_digit, b_digit, total;
    int tmp = 0;
    int i = 0;
    int a_len = strlen(a);
    int b_len = strlen(b);
    while (i <= b_len || i <= a_len) {
        a_digit = getDigit(a[i]);
        b_digit = getDigit(b[i]);
        if (i > b_len) b_digit = 0;
        total = a_digit + b_digit + tmp;
        tmp = total / 16;
        a[i] = total % 16 + '0';
        if (total % 16 >= 10) a[i] = total % 16 + 'W';
        i++;
    }
    removeZeroes(a);
    while (ge(a, n)) {
        sub(a, n);
    }
}

void mult(char* a, char* b) {
    char a0[LEN] = { '0', };
    char b0[LEN] = {};
    b0[0] = '0';
    char as[16][LEN];
    for (int i = 0; i < 16; i++) {
        strcpy(as[i], b0);
        add(b0, a);
    }
    int ptr = 0;
    int b_digit;
    while (b[ptr]) {
        b_digit = getDigit(b[ptr]);
        strcpy(b0, as[b_digit]);
        if (ptr) shr(b0, ptr);
        add(a0, b0);
        ptr++;
    }
    strcpy(a, a0);
}


void divide2(char* a) {
    bool carry = false;
    for (int ptr = strlen(a) - 1; ptr >= 0; ptr--) {
        int a_digit = getDigit(a[ptr]);
        if (carry) {
            carry = false;
            a_digit += 16;
        }
        a[ptr] = getChar(a_digit / 2);
        if (a_digit % 2) {
            carry = true;
        }
    }
    removeZeroes(a);
}

bool even(char* b) {
    return b[0] == '0' || b[0] == '2' || b[0] == '4' || b[0] == '6' || b[0] == '8' || b[0] == 'a' || b[0] == 'c' || b[0] == 'e';
}

void power(char* a, char* b) {
    if (strlen(b) == 1 and b[0] == '1') return;
    if (even(b)) {
        divide2(b);
        mult(a, a);
        power(a, b);
    }
    else {
        b[0] = getChar(getDigit(b[0]) - 1);
        char a0[LEN] = {};
        strcpy(a0, a);
        power(a, b);
        mult(a, a0);
    }
}

int main(int argc, char* argv[], char* envp[])
{
    printf("Obtaining flag...\n");
    flip(d);
    power(c, d);
    printf("%s\n", "Here is the...wait, where did it go-");
}