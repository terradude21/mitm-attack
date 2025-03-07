#include <stdint.h>
#include <string.h>

#include "aes.h"
#include "haraka.h"

const uint64_t haraka_rc[64] = {
    0xb2c5fef075817b9d, 0x0684704ce620c00a, 0x640f6ba42f08f717, 0x8b66b4e188f3a06b, 
    0xcf029d609f029114, 0x3402de2d53f28498, 0xbbf3bcaffd5b4f79, 0x0ed6eae62e7b4f08, 
    0x79eecd1cbe397044, 0xcbcfb0cb4872448b, 0x8d5335ed2b8a057b, 0x7eeacdee6e9032b7, 
    0xe2412761da4fef1b, 0x67c28f435e2e7cd0, 0x675ffde21fc70b3b, 0x2924d9b0afcacc07, 
    0xecdb8fcab9d465ee, 0xab4d63f1e6867fe9, 0x5b2a404fad037e33, 0x1c30bf84d4b7cd64, 
    0x69028b2e8df69800, 0xb2cc0bb9941723bf, 0x4aaa9ec85c9d2d8a, 0xfa0478a6de6f5572, 
    0x0efa4f2e29129fd4, 0xdfb49f2b6b772a12, 0x32d611aebb6a12ee, 0x1ea10344f449a236, 
    0x5f9600c99ca8eca6, 0xaf0449884b050084, 0x78a2c7e327e593ec, 0x21025ed89d199c4f, 
    0xb9282ecd82d40173, 0xbf3aaaf8a759c9b7, 0x37f2efd910307d6b, 0x6260700d6186b017, 
    0x81c29153f6fc9ac6, 0x5aca45c221300443, 0x2caf92e836d1943a, 0x9223973c226b68bb, 
    0x6cbab958e51071b4, 0xd3bf9238225886eb, 0x933dfddd24e1128d, 0xdb863ce5aef0c677, 
    0x83e48de3cb2212b1, 0xbb606268ffeba09c, 0x2db91a4ec72bf77d, 0x734bd3dce2e4d19c, 
    0x4b1415c42cb3924e, 0x43bb47c361301b43, 0x03b231dd16eb6899, 0xdba775a8e707eff6, 
    0x8e5e23027eca472c, 0x6df3614b3c755977, 0x6d1be5b9b88617f9, 0xcda75a17d6de7d77, 
    0x9d6c069da946ee5d, 0xec6b43f06ba8e9aa, 0xa25311593bf327c1, 0xcb1e6950f957332b, 
    0xe4ed0353600ed0d9, 0x2cee0c7500da619c, 0x80bbbabc63a4a350, 0xf0b1a5a196e90cab
};

const int p_mix[16] = {3, 11, 7, 15, 8, 0, 12, 4, 9, 1, 13, 5, 2, 10, 6, 14};
const int p_mix_inv[16] = {5, 9, 12, 0, 7, 11, 14, 2, 4, 8, 13, 1, 6, 10, 15, 3};

/*
 * Haraka mixing operation.
 * Applies permutation p to the columns of the Haraka state s.
 */
void mix(unsigned char *s, const int *p)
{
    unsigned char t[64];

    for (int i = 0; i < 16; i++) {
        memcpy(t + i*4, s + p[i]*4, 4);
    }

    memcpy(s, t, 64);
}

/* 
 * Haraka permutation: 512 bits -> 512 bits
 * The permutation is simplified for the attack:
 * 4 rounds instead of 5, the last mixing operation is omitted.
 */
void haraka512_p(unsigned char *out, const unsigned char *in)
{
    unsigned char s[64];

    memcpy(s, in, 64);

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < 4; k++) {
                aes(s + k*16, haraka_rc[16*i + 8*j + 2*k], haraka_rc[16*i + 8*j + 2*k + 1]);
            }
        }

        if (i < 3) {
            mix(s, p_mix);
        }
    }

    memcpy(out, s, 64);
}

/* 
 * Haraka inverse permutation: 512 bits -> 512 bits
 * The permutation is simplified for the attack:
 * 4 rounds instead of 5, the last mixing operation is omitted.
 */
void haraka512_p_inv(unsigned char *out, const unsigned char *in)
{
    unsigned char s[64];

    memcpy(s, in, 64);

    for (int i = 0; i < 4; i++) {

        if (i > 0) {
            mix(s, p_mix_inv);
        }

        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < 4; k++) {
                aes_inv(s + k*16, haraka_rc[56 - (16*i + 8*j) + 2*k], haraka_rc[57 - (16*i + 8*j) + 2*k]);
            }
        }
    }

    memcpy(out, s, 64);
}

/*
 * XORs the message block m into the outer part of the state s.
 */
void absorb(unsigned char *s, const unsigned char *m)
{
    for (int i = 0; i < 32; i++)
        s[i] ^= m[i];
}

/*
 * Haraka sponge construction.
 * Hashes an arbitrary length input to an arbitrary length output.
 */
void haraka_s(unsigned char *out, size_t outlen, const unsigned char *in, size_t inlen)
{
    unsigned char s[64];
    unsigned char f[32];
    size_t n = inlen / 32;
    size_t m = outlen / 32;
    int d = inlen % 32;
    int e = outlen % 32;

    /* Initialize */
    memset(s, 0, 64);

    /* Absorb */
    for (size_t r = 0; r < n; r++) {
        absorb(s, in + 32*r);
        haraka512_p(s, s);
    }

    memcpy(f, in + (32 * n), d);
    f[d] = 0x1f;
    memset(f + (d + 1), 0, 31 - d);
    f[31] |= 0x80;

    absorb(s, f);
    haraka512_p(s, s);

    /* Squeeze */
    for (size_t r = 0; r < m; r++) {
        memcpy(out + (32 * r), s, 32);
        haraka512_p(s, s);
    }

    memcpy(out + (32 * m), s, e);
}
