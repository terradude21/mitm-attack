#include <stdint.h>
#include <string.h>

#include "haraka.h"

static const unsigned char aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint64_t haraka_rc_default[80] = {
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
    0xe4ed0353600ed0d9, 0x2cee0c7500da619c, 0x80bbbabc63a4a350, 0xf0b1a5a196e90cab, 
    0xab0dde30938dca39, 0xae3db1025e962988, 0x8814f3a82e75b442, 0x17bb8f38d554a40b, 
    0xaeb6b779360a16f6, 0x34bb8a5b5f427fd7, 0x43ce5918ffbaafde, 0x26f65241cbe55438, 
    0xa2ca9cf7839ec978, 0x4ce99a54b9f3026a, 0x40c06e2822901235, 0xae51a51a1bdff7be, 
    0xc173bc0f48a659cf, 0xa0c1613cba7ed22b, 0x4ad6bdfde9c59da1, 0x756acc0302288288
};

static const int p_mix[16] = {3, 11, 7, 15, 8, 0, 12, 4, 9, 1, 13, 5, 2, 10, 6, 14};

static const int trunc[8] = {2, 3, 6, 7, 8, 9, 12, 13};

static uint64_t haraka_rc[80];

/* 
 * Perform one AES round on the 128-bit state a.
 * (k0, k1) is the round key.
 */
static void aes(unsigned char *a, const uint64_t k0, const uint64_t k1)
{
    unsigned char t;
    unsigned char a0, a1, a2, a3;
    unsigned char a02, a12, a22, a32;
    unsigned char a03, a13, a23, a33;
    unsigned char b0, b1, b2, b3;

    /* SubBytes */
    for (int i = 0; i < 16; i++) {
        a[i] = aes_sbox[a[i]];
    }

    /* ShiftRows */
    t = a[1]; a[1] = a[5]; a[5] = a[9]; a[9] = a[13]; a[13] = t;
    t = a[2]; a[2] = a[10]; a[10] = t; t = a[6]; a[6] = a[14]; a[14] = t;
    t = a[3]; a[3] = a[15]; a[15] = a[11]; a[11] = a[7]; a[7] = t;

    /* MixColumns */
    for (int j = 0; j < 16; j += 4) {
        a0 = a[j]; a1 = a[j+1]; a2 = a[j+2]; a3 = a[j+3];
        a02 = (a0 << 1) ^ (a0 & 0x80 ? 0x1b : 0);
        a12 = (a1 << 1) ^ (a1 & 0x80 ? 0x1b : 0);
        a22 = (a2 << 1) ^ (a2 & 0x80 ? 0x1b : 0);
        a32 = (a3 << 1) ^ (a3 & 0x80 ? 0x1b : 0);
        a03 = a02 ^ a0;
        a13 = a12 ^ a1;
        a23 = a22 ^ a2;
        a33 = a32 ^ a3;
        b0 = a02 ^ a13 ^ a2  ^ a3 ;
        b1 = a0  ^ a12 ^ a23 ^ a3 ;
        b2 = a0  ^ a1  ^ a22 ^ a33;
        b3 = a03 ^ a1  ^ a2  ^ a32;
        a[j] = b0; a[j+1] = b1; a[j+2] = b2; a[j+3] = b3;
    }

    /* AddKey */
    for (int k = 0; k < 16; k++) {
        a[k] ^= (unsigned char)((k < 8 ? k0 : k1) >> ((k % 8) * 8));
    }
}

/*
 * Haraka mixing operation.
 * Permutes the columns of the Haraka state s.
 */
static void mix(unsigned char *s)
{
    unsigned char t[64];

    for (int i = 0; i < 16; i++) {
        memcpy(t + i*4, s + p_mix[i]*4, 4);
    }

    memcpy(s, t, 64);
}

/*
 * Initialize the Haraka round constants (used as AES keys) to the default values.
 * This or seed_rc() must be called before using the Haraka functions.
 */
void init_rc()
{
    memcpy(haraka_rc, haraka_rc_default, 640);
}

/*
 * Initialize the Haraka round constants (used as AES keys) according to a seed of arbitrary length.
 * This or init_rc() must be called before using the Haraka functions.
 */
void seed_rc(const unsigned char *seed, size_t seedlen)
{
    unsigned char s[640];

    init_rc();

    haraka_s(s, 640, seed, seedlen);

    memcpy(haraka_rc, s, 640);
}

/* 
 * Haraka permutation: 512 bits -> 512 bits
 */
void haraka512_p(unsigned char *out, const unsigned char *in)
{
    unsigned char s[64];

    memcpy(s, in, 64);

    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < 4; k++) {
                aes(s + k*16, haraka_rc[16*i + 8*j + 2*k], haraka_rc[16*i + 8*j + 2*k + 1]);
            }
        }

        mix(s);
    }

    memcpy(out, s, 64);
}

/* 
 * Simple Haraka hash function: 512 bits -> 256 bits
 * One permutation, xor input and output, truncate to 256 bits.
 */
void haraka512(unsigned char *out, const unsigned char *in)
{
    unsigned char pout[64];
    haraka512_p(pout, in);

    for (int i = 0; i < 64; i++)
        pout[i] ^= in[i];

    for (int i = 0; i < 32; i++) {
        out[i] = pout[trunc[i/4]*4 + i%4];
    }
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
        for (int i = 0; i < 32; i++) {
            s[i] ^= in[32*r + i];
        }
        haraka512_p(s, s);
    }

    memcpy(f, in + (32 * n), d);
    f[d] = 0x1f;
    memset(f + (d + 1), 0, 31 - d);
    f[31] |= 0x80;

    for (int i = 0; i < 32; i++)
        s[i] ^= f[i];

    haraka512_p(s, s);

    /* Squeeze */
    for (size_t r = 0; r < m; r++) {
        memcpy(out + (32 * r), s, 32);
        haraka512_p(s, s);
    }

    memcpy(out + (32 * m), s, e);
}
