#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aes.h"
#include "attack.h"
#include "haraka.h"
#include "precalc.h"

#define DOF_RED 0
#define DOF_BLUE 0

void test_mixcol()
{
    unsigned char in[16] = {
        0xf2, 0x0a, 0x22, 0x5c, 
        0x01, 0x01, 0x01, 0x01,
        0xc6, 0xc6, 0xc6, 0xc6,
        0xd4, 0xd4, 0xd4, 0xd5
    };

    aes_mixcol(in);

    for (int i = 0; i < 16; i++) {
        printf("%.2hhx ", in[i]);
        if (i % 4 == 3) printf("\n");
    }

    /*
     * Expected:
     * 9f dc 58 9d
     * 01 01 01 01
     * c6 c6 c6 c6
     * d5 d5 d7 d6
     */

    aes_mixcol_inv(in);

    printf("\n");
    for (int i = 0; i < 16; i++) {
        printf("%.2hhx ", in[i]);
        if (i % 4 == 3) printf("\n");
    }
}

void test_haraka()
{
    unsigned char s[64];

    for (int i = 0; i < 64; i++)
        s[i] = i;

    haraka512_p(s, s);

    for (int i = 0; i < 64; i++) {
        printf("%.2hhx ", s[i]);
    }

    printf("\n");

    haraka512_p_inv(s, s);

    for (int i = 0; i < 64; i++) {
        printf("%.2hhx ", s[i]);
    }
}

void run_attack()
{
    unsigned char rf[12], bf[12], ff[8], rb[12], bb[12], fb[8], z[16], x[32];
    unsigned char message[160], target[32], output[160], target2[32];

    struct timespec t_start, t_end;

    // C standard random library is not guaranteed to be good, but should be enough here
    srand((unsigned int)time(NULL));

    for (int i = 0; i < 159; i++)
        message[i] = rand();
    message[159] = 0x9f;

    haraka_s(target, 32, message, 159);

    printf("message:\n");
    for (int i = 0; i < 159; i++) {
        printf("%.2hhx ", message[i]);
    }
    printf("\ntarget:\n");
    for (int i = 0; i < 32; i++) {
        printf("%.2hhx ", target[i]);
    }

    precalc(rf, bf, ff, rb, bb, fb, z, x, message);

    timespec_get(&t_start, TIME_UTC);
    int success = attack(output, message, message + 128, rf, bf, ff, rb, bb, fb, DOF_RED, DOF_BLUE, z, x, target);
    timespec_get(&t_end, TIME_UTC);

    if (success == 0) {
        printf("\nattack found:\n");
        for (int i = 0; i < 159; i++) {
            printf("%.2hhx ", output[i]);
        }
        if (memcmp(message, output, 159) == 0) {
            printf("\nattack result identical to original\n");
        } else {
            haraka_s(target2, 32, output, 159);
            if (memcmp(target, target2, 32) == 0) {
                printf("\nattack result is different, but valid\n");
            } else {
                printf("\nattack result is invalid\n");
            }
        }
    } else {
        printf("\nattack found nothing\n");
    }

    double t1 = t_start.tv_sec + t_start.tv_nsec / 1.0e9;
    double t2 = t_end.tv_sec + t_end.tv_nsec / 1.0e9;
    printf("\ntime taken: %f seconds\n", t2 - t1);
}

int main()
{
    // test_mixcol();
    // test_haraka();
    run_attack();
}
