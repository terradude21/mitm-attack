#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aes.h"
#include "haraka.h"

static int inc_array(unsigned char *a, const int len)
{
    int i;
    for (i = 0; i < len; i++) {
        a[i]++;
        if (a[i]) break;
    }
    return i != len;
}

static void mixcol_red_f(unsigned char *mr, const unsigned char *s)
{
    mr[0] = gdouble(s[3]) ^ s[2];
    mr[1] = gdouble(s[5]) ^ s[5] ^ s[6];
    mr[2] = gdouble(s[9]) ^ s[8];
    mr[3] = gdouble(s[15]) ^ s[15] ^ s[12];
}

int attack(unsigned char *m, const unsigned char *m1, const unsigned char *m5,
    const unsigned char *rf, const unsigned char *bf, const unsigned char *ff,
    const unsigned char *rb, const unsigned char *bb, const unsigned char *fb,
    const int dof_red, const int dof_blue, const unsigned char *z, const unsigned char *x,
    const unsigned char *t)
{
    unsigned char s[64];
    unsigned char match[16], match_r[16], match_b[16];
    unsigned char save_outer[32];
    unsigned char *iter_red, *table_u;

    memset(s, 0, 32);
    memcpy(s + 32, z, 16);
    memset(s + 48, 0, 16);

    for (int j = 0; j < 2; j++) {
        aes_inv(s + 32, haraka_rc[60 - 8*j], haraka_rc[61 - 8*j]);
    }
    mix(s, p_mix_inv);
    for (int k = 0; k < 4; k++) {
        aes_inv(s + k*16, haraka_rc[40 + 2*k], haraka_rc[41 + 2*k]);
        aes_addkey(s + k*16, haraka_rc[32 + 2*k], haraka_rc[33 + 2*k]);
    }

    for (int i = 0, n = 3; i < 16; i++) {
        match[i] = s[n];
        n += (n % 4 == 3) ? 1 : 5;
    }

    memcpy(s, m1, 32);
    memset(s + 32, 0, 32);
    haraka512_p(s, s);
    memcpy(save_outer, s, 32);

    for (int j = 0; j < 2; j++) {
        for (int k = 2; k < 4; k++) {
            aes(s + k*16, haraka_rc[8*j + 2*k], haraka_rc[8*j + 2*k + 1]);
        }
    }
    for (int i = 0; i < 4; i++) {
        s[i*8+4] = s[i*8+5] = s[i*8+6] = 0;
        s[i*8+3] = ff[i*2];
        s[i*8+7] = ff[i*2+1];
    }
    int n = 0;
    for (int i = 0; i < 12 - dof_red; i++) {
        s[n] = rf[i];
        n += (n % 4 == 2) ? 6 : 1;
    }

    iter_red = malloc(dof_red);
    memset(iter_red, 0, dof_red);
    table_u = malloc(28 * (1ULL << dof_red*8));
    int u_index = 0;
    do {

        for (int i = 0; i < dof_red; i++) {
            s[n] = iter_red[i];
            n += (n % 4 == 2) ? 6 : 1;
        }

        mix(s, p_mix);
        for (int j = 0; j < 2; j++) {
            aes(s + 16, haraka_rc[18 + 8*j], haraka_rc[19 + 8*j]);
            aes(s + 48, haraka_rc[22 + 8*j], haraka_rc[23 + 8*j]);
        }
        mix(s, p_mix);
        for (int k = 0; k < 4; k++) {
            aes_subbyte(s + k*16, aes_sbox);
            aes_shiftrow(s + k*16, 0);
            mixcol_red_f(match_r + k*4, s + k*16);
        }

        memcpy(table_u + u_index*28, match_r, 16);
        memcpy(table_u + u_index*28 + 16, rf, 12 - dof_red);
        memcpy(table_u + u_index*28 + (28 - dof_red), iter_red, dof_red);
        u_index++;

    } while (inc_array(iter_red, dof_red));
}

int full_attack(unsigned char *m, const unsigned char *t)
{
    unsigned char m1[32], m5[32], x[32], zero[16];

    // I know rand() is bad, look for an alternative later
    srand(time(NULL));

    for (int i = 0; i < 32; i++) {
        m1[i] = rand();
        x[i] = rand();
        if (i < 31) m5[i] = rand();
    }
    m5[31] = 0x9f;

    for (int i = 0; i < 16; i++)
        zero[i] = 0;

    return attack(m, m1, m5, NULL, NULL, zero, NULL, NULL, zero, 12, 12, zero, x, t);
}
