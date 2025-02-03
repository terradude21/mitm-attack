#include <string.h>

#include "aes.h"
#include "haraka.h"
#include "precalc.h"

static const int rb_index[12] = {0, 1, 2, 12, 13, 14, 20, 21, 22, 24, 25, 26};
static const int bb_index[12] = {4, 5, 6, 8, 9, 10, 16, 17, 18, 28, 29, 30};

static void absorb(unsigned char *s, const unsigned char *m, const int len)
{
    for (int i = 0; i < len; i++)
        s[i] ^= m[i];
}

/* 
 * red, blue, fixed - forward, backward
 * z is the forward/backward mitm target (all zeros in full attack)
 * x is inner part at the end
 * input length is 159 bytes (five blocks and one byte room for padding)
 */
void precalc(unsigned char *rf, unsigned char *bf, unsigned char *ff,
    unsigned char *rb, unsigned char *bb, unsigned char *fb,
    unsigned char *z, unsigned char *x, const unsigned char *in)
{
    unsigned char s[64];
    unsigned char t[64];

    memcpy(s, in, 32);
    memset(s + 32, 0, 32);

    haraka512_p(s, s);

    absorb(s, in + 32, 32);

    memcpy(t, s, 64);

    for (int j = 0; j < 2; j++) {
        for (int k = 0; k < 4; k++) {
            aes(t + k*16, haraka_rc[8*j + 2*k], haraka_rc[8*j + 2*k + 1]);
        }
    }

    for (int i = 0; i < 4; i++) {
        rf[i*3] = t[i*8]; rf[i*3+1] = t[i*8+1]; rf[i*3+2] = t[i*8+2];
        bf[i*3] = t[i*8+4]; bf[i*3+1] = t[i*8+5]; bf[i*3+2] = t[i*8+6];
        ff[i*2] = t[i*8+3]; ff[i*2+1] = t[i*8+7];
    }

    haraka512_p(s, s);

    memcpy(z, s + 32, 16);

    absorb(s, in + 64, 32);
    haraka512_p(s, s);

    memcpy(t, s, 64);

    for (int j = 0; j < 2; j++) {
        for (int k = 0; k < 4; k++) {
            aes_inv(t + k*16, haraka_rc[56 - 8*j + 2*k], haraka_rc[57 - 8*j + 2*k]);
        }
    }

    for (int i = 0; i < 12; i++) {
        rb[i] = t[rb_index[i]];
        bb[i] = t[bb_index[i]];
    }

    for(int i = 0; i < 8; i++)
        fb[i] = t[i*4+3];

    absorb(s, in + 96, 32);
    haraka512_p(s, s);

    absorb(s, in + 128, 31);
    s[31] ^= 0x9f;
    haraka512_p(s, s);

    memcpy(x, s + 32, 32);
}
