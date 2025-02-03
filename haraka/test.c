#include <stdio.h>

#include "haraka.h"

int main()
{
    unsigned char input[64];
    unsigned char output[32];

    for (int i = 0; i < 64; i++)
        input[i] = i;

    init_rc();
    haraka512(output, input);

    for (int i = 0; i < 32; i++) {
        printf("%.2hhx ", output[i]);
    }
}

/*
 * Expected output:
 * be 7f 72 3b 4e 80 a9 98 13 b2 92 28 7f 30 6f 62
 * 5a 6d 57 33 1c ae 5f 34 dd 92 77 b0 94 5b e2 aa
 */
