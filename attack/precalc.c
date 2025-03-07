#include <string.h>

#include "aes.h"
#include "attack.h"
#include "haraka.h"
#include "precalc.h"

/* 
 * Precalculates and stores values for the attack.
 * rf, bf, ff, rb, bb, fb = red (12 bytes), blue (12 bytes), fixed (8 bytes) - forward, backward
 * z is the forward/backward mitm target (16 bytes, all zeros in full attack)
 * x is inner part at the end of the sponge process (32 bytes)
 * input length is 159 bytes (five blocks, leave one byte room for padding)
 */
void precalc(unsigned char *rf, unsigned char *bf, unsigned char *ff,
    unsigned char *rb, unsigned char *bb, unsigned char *fb,
    unsigned char *z, unsigned char *x, const unsigned char *in)
{
    unsigned char s[64];
    unsigned char t[64];
    unsigned char m5[32];

    memcpy(s, in, 32);
    memset(s + 32, 0, 32);

    haraka512_p(s, s);

    absorb(s, in + 32);

    memcpy(t, s, 64);

    for (int j = 0; j < 2; j++) {
        for (int k = 0; k < 4; k++) {
            aes(t + k*16, haraka_rc[8*j + 2*k], haraka_rc[8*j + 2*k + 1]);
        }
    }

    for (int i = 0; i < 12; i++) {
        rf[i] = t[rf_index[i]];
        bf[i] = t[bf_index[i]];
    }
    for (int i = 0; i < 8; i++)
        ff[i] = t[i*4+3];

    haraka512_p(s, s);

    memcpy(z, s + 32, 16);

    absorb(s, in + 64);
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
    for (int i = 0; i < 8; i++)
        fb[i] = t[i*4+3];

    absorb(s, in + 96);
    haraka512_p(s, s);

    memcpy(m5, in + 128, 31);
    m5[31] = 0x9f;
    absorb(s, m5);
    haraka512_p(s, s);

    memcpy(x, s + 32, 32);
}
