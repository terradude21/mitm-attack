#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aes.h"
#include "attack.h"
#include "haraka.h"

const int rf_index[12] = {0, 1, 2, 8, 9, 10, 16, 17, 18, 24, 25, 26};
const int bf_index[12] = {4, 5, 6, 12, 13, 14, 20, 21, 22, 28, 29, 30};
const int rb_index[12] = {0, 1, 2, 12, 13, 14, 20, 21, 22, 24, 25, 26};
const int bb_index[12] = {4, 5, 6, 8, 9, 10, 16, 17, 18, 28, 29, 30};

/* 
 * Helper function to increment byte array a of length len,
 * as if it were one integer (LSB first).
 * Returns zero if it overflows and loops to an array of zeros.
 */
static int inc_array(unsigned char *a, const int len)
{
    int i;
    for (i = 0; i < len; i++) {
        a[i]++;
        if (a[i]) break;
    }
    return i != len;
}

#define MC2(x) (gdouble(x))
#define MC3(x) (MC2(x) ^ (x))
#define MC9(x) (MC2(MC2(MC2(x))) ^ (x))
#define MCB(x) (MC2(MC2(MC2(x)) ^ (x)) ^ (x))
#define MCD(x) (MC2(MC2(MC3(x))) ^ (x))
#define MCE(x) (MC2(MC2(MC3(x)) ^ (x)))

#define EX_32_4(x, i) (((x) >> ((i)*4)) & 0xf)

/* 
 * Helper function to multiply x by y in the AES Galois field.
 * Only possible values for y are 1, 2, 3, 9, 11, 13, 14, returns zero otherwise.
 */
static unsigned char mult_gf(unsigned char x, unsigned char y)
{
    switch (y)
    {
    case 1: return x;
    case 2: return MC2(x);
    case 3: return MC3(x);
    case 9: return MC9(x);
    case 11: return MCB(x);
    case 13: return MCD(x);
    case 14: return MCE(x);
    
    default: return 0;
    }
}

/* 
 * Helper function to do a "half" AES MixColumns.
 * Stores the 4 relevant bytes in a.
 * s is the 16-byte AES state.
 * is are the indices of the bytes to consider, mat are the matrix elements
 * (both packed as a 32-bit integer)
 */
static void mixcol_partial(unsigned char *a, const unsigned char *s, const uint32_t is, const uint32_t mat)
{
    for (int i = 0; i < 8; i += 2)
        a[i/2] = mult_gf(s[EX_32_4(is, i)], EX_32_4(mat, i)) ^ mult_gf(s[EX_32_4(is, i+1)], EX_32_4(mat, i+1));
}

/* 
 * Performs the attack to find a 160 byte message (159 bytes + padding) and stores it in m.
 * First and last message block (including padding) are provided as m1 and m5.
 * (32 bytes each, can be chosen randomly)
 * Precalculated values are provided as found by precalc.
 * dof_red and dof_blue are degrees of freedom, in bytes, for red and blue respectively.
 * (between 0 and 12, might only work up to a smaller value due to data size limitations)
 * (up to 7 should be fine, which already has impractical complexity)
 * t is the target hash output (32 bytes).
 * Returns zero if attack is successful.
 */
int attack(unsigned char *m, const unsigned char *m1, const unsigned char *m5,
    const unsigned char *rf, const unsigned char *bf, const unsigned char *ff,
    const unsigned char *rb, const unsigned char *bb, const unsigned char *fb,
    const int dof_red, const int dof_blue, const unsigned char *z, const unsigned char *x,
    const unsigned char *t)
{
    unsigned char s[64];
    unsigned char match[16], match_r[16], match_b[16];
    unsigned char save_outer[32], mitm_init[64];
    unsigned char *iter, *table_u, *table_l;

    size_t entry_size_u = 16 + dof_red;
    size_t num_entries_u = (1ULL << dof_red*8);
    size_t num_entries_l = 0;
    size_t u_index = 0;

    /* === FORWARD MITM === */

    /* derive matching point */
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

    /* prepare initial state */
    memcpy(s, m1, 32);
    memset(s + 32, 0, 32);
    haraka512_p(s, s);
    memcpy(save_outer, s, 32);

    for (int j = 0; j < 2; j++) {
        for (int k = 2; k < 4; k++) {
            aes(s + k*16, haraka_rc[8*j + 2*k], haraka_rc[8*j + 2*k + 1]);
        }
    }
    for (int i = 0; i < 8; i++) {
        s[i*4+3] = ff[i];
    }
    for (int i = 0; i < 12 - dof_red; i++) {
        s[rf_index[i]] = rf[i];
    }
    for (int i = 0; i < 12 - dof_blue; i++) {
        s[bf_index[i]] = bf[i];
    }

    memcpy(mitm_init, s, 64);

    /* iterate red */
    iter = calloc(dof_red, 1);
    table_u = malloc(entry_size_u * num_entries_u);
    do {

        for (int i = 0; i < dof_red; i++) {
            s[rf_index[12 - dof_red + i]] = iter[i];
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
            mixcol_partial(match_r + k*4, s + k*16, 0xfc986532, 0x31211321);
        }

        memcpy(table_u + u_index*entry_size_u, match_r, 16);
        memcpy(table_u + u_index*entry_size_u + 16, iter, dof_red);
        u_index++;

        memcpy(s, mitm_init, 64);

    } while (inc_array(iter, dof_red));
    free(iter);

    /* iterate blue */
    iter = calloc(dof_blue, 1);
    table_l = malloc(48 * num_entries_l);
    do {

        for (int i = 0; i < dof_blue; i++) {
            s[bf_index[12 - dof_blue + i]] = iter[i];
        }

        mix(s, p_mix);
        for (int j = 0; j < 2; j++) {
            aes(s, haraka_rc[16 + 8*j], haraka_rc[17 + 8*j]);
            aes(s + 32, haraka_rc[20 + 8*j], haraka_rc[21 + 8*j]);
        }
        mix(s, p_mix);
        for (int k = 0; k < 4; k++) {
            aes_subbyte(s + k*16, aes_sbox);
            aes_shiftrow(s + k*16, 0);
            mixcol_partial(match_b + k*4, s + k*16, 0xedba7410, 0x21131213);
        }

        for (int i = 0; i < 16; i++)
            match_b[i] ^= match[i];

        for (size_t index = 0; index < num_entries_u; index++) {

            unsigned char *entry = table_u + index*entry_size_u;
            unsigned char *r = entry + 16; 

            if (memcmp(entry, match_b, 16) == 0) {

                memcpy(s, mitm_init, 64);
                for (int i = 0; i < dof_red; i++) {
                    s[rf_index[12 - dof_red + i]] = r[i];
                }
                for (int i = 0; i < dof_blue; i++) {
                    s[bf_index[12 - dof_blue + i]] = iter[i];
                }

                for (int j = 0; j < 2; j++) {
                    for (int k = 0; k < 4; k++) {
                        aes_inv(s + k*16, haraka_rc[8 - 8*j + 2*k], haraka_rc[9 - 8*j + 2*k]);
                    }
                }

                unsigned char m2[32], l_key[16];
                for (int i = 0; i < 32; i++)
                    m2[i] = s[i] ^ save_outer[i];

                haraka512_p(s, s);
                memcpy(l_key, s + 48, 16);

                num_entries_l++;
                table_l = realloc(table_l, 48 * num_entries_l);
                memcpy(table_l + 48*(num_entries_l-1), l_key, 16);
                memcpy(table_l + 48*(num_entries_l-1) + 16, m2, 32);

                break;

            }
        }

        memcpy(s, mitm_init, 64);

    } while (inc_array(iter, dof_blue));
    free(iter);

    /* === BACKWARD MITM === */

    /* derive matching point */
    memcpy(s + 32, z, 16);

    for (int j = 0; j < 2; j++) {
        aes(s + 32, haraka_rc[4 + 8*j], haraka_rc[5 + 8*j]);
    }
    mix(s, p_mix);
    for (int k = 0; k < 4; k++) {
        aes_subbyte(s + k*16, aes_sbox);
        aes_shiftrow(s + k*16, 0);
    }

    for (int i = 0, n = 1; i < 16; i++) {
        match[i] = s[n];
        n += (n % 4 == 0) ? 7 : (n == 45) ? 4 : (n == 14) ? 2 : 3;
    }

    /* prepare initial state */
    memcpy(s, t, 32);
    memcpy(s + 32, x, 32);
    haraka512_p_inv(s, s);
    absorb(s, m5);
    haraka512_p_inv(s, s);
    memcpy(save_outer, s, 32);

    for (int j = 0; j < 2; j++) {
        for (int k = 2; k < 4; k++) {
            aes_inv(s + k*16, haraka_rc[56 - 8*j + 2*k], haraka_rc[57 - 8*j + 2*k]);
        }
    }
    for (int i = 0; i < 8; i++) {
        s[i*4+3] = fb[i];
    }
    for (int i = 0; i < 12 - dof_red; i++) {
        s[rb_index[i]] = rb[i];
    }
    for (int i = 0; i < 12 - dof_blue; i++) {
        s[bb_index[i]] = bb[i];
    }

    memcpy(mitm_init, s, 64);

    /* iterate red */
    iter = calloc(dof_red, 1);
    u_index = 0;
    do {

        for (int i = 0; i < dof_red; i++) {
            s[rb_index[12 - dof_red + i]] = iter[i];
        }

        mix(s, p_mix_inv);
        for (int j = 0; j < 2; j++) {
            aes_inv(s, haraka_rc[40 - 8*j], haraka_rc[41 - 8*j]);
            aes_inv(s + 48, haraka_rc[46 - 8*j], haraka_rc[47 - 8*j]);
        }
        mix(s, p_mix_inv);
        for (int k = 0; k < 4; k++) {
            aes_inv(s + k*16, haraka_rc[24 + 2*k], haraka_rc[25 + 2*k]);
            aes_addkey(s + k*16, haraka_rc[16 + 2*k], haraka_rc[17 + 2*k]);
            mixcol_partial(match_r + k*4, s + k*16, 0xdcb87621, (k == 0 || k == 3) ? 0x9deb9dbe : 0xe9bde9db);
        }

        memcpy(table_u + u_index*entry_size_u, match_r, 16);
        memcpy(table_u + u_index*entry_size_u + 16, iter, dof_red);
        u_index++;

        memcpy(s, mitm_init, 64);

    } while (inc_array(iter, dof_red));
    free(iter);

    /* iterate blue */
    iter = calloc(dof_blue, 1);
    do {

        for (int i = 0; i < dof_blue; i++) {
            s[bb_index[12 - dof_blue + i]] = iter[i];
        }

        mix(s, p_mix_inv);
        for (int j = 0; j < 2; j++) {
            aes_inv(s + 16, haraka_rc[42 - 8*j], haraka_rc[43 - 8*j]);
            aes_inv(s + 32, haraka_rc[44 - 8*j], haraka_rc[45 - 8*j]);
        }
        mix(s, p_mix_inv);
        for (int k = 0; k < 4; k++) {
            aes_inv(s + k*16, haraka_rc[24 + 2*k], haraka_rc[25 + 2*k]);
            aes_addkey(s + k*16, haraka_rc[16 + 2*k], haraka_rc[17 + 2*k]);
            mixcol_partial(match_b + k*4, s + k*16, 0xfea95430, (k == 0 || k == 3) ? 0xbe9dbed9 : 0xdbe9db9e);
        }

        for (int i = 0; i < 16; i++)
            match_b[i] ^= match[i];

        for (size_t index_u = 0; index_u < num_entries_u; index_u++) {

            unsigned char *entry_u = table_u + index_u*entry_size_u;
            unsigned char *r = entry_u + 16; 
    
            if (memcmp(entry_u, match_b, 16) == 0) {
    
                memcpy(s, mitm_init, 64);
                for (int i = 0; i < dof_red; i++) {
                    s[rb_index[12 - dof_red + i]] = r[i];
                }
                for (int i = 0; i < dof_blue; i++) {
                    s[bb_index[12 - dof_blue + i]] = iter[i];
                }
    
                for (int j = 0; j < 2; j++) {
                    for (int k = 0; k < 4; k++) {
                        aes(s + k*16, haraka_rc[48 + 8*j + 2*k], haraka_rc[49 + 8*j + 2*k]);
                    }
                }
    
                unsigned char m4[32], l_find[16];
                for (int i = 0; i < 32; i++)
                    m4[i] = s[i] ^ save_outer[i];
    
                haraka512_p_inv(s, s);
                memcpy(l_find, s + 48, 16);
    
                for (size_t index_l = 0; index_l < num_entries_l; index_l++) {

                    unsigned char *entry_l = table_l + index_l*48;
                    unsigned char *m2 = entry_l + 16; 
            
                    if (memcmp(entry_l, l_find, 16) == 0) {

                        unsigned char t[64];

                        memcpy(t, m1, 32);
                        memset(t + 32, 0, 32);
                        haraka512_p(t, t);
                        absorb(t, m2);
                        haraka512_p(t, t);

                        memcpy(m, m1, 32);
                        memcpy(m + 32, m2, 32);
                        for (int i = 0; i < 32; i++)
                            m[64 + i] = s[i] ^ t[i];
                        memcpy(m + 96, m4, 32);
                        memcpy(m + 128, m5, 32);

                        free(iter);
                        free(table_u);
                        free(table_l);

                        return ATTACK_SUCCESS;

                    }
                }
    
                break;
    
            }
        }
    
        memcpy(s, mitm_init, 64);

    } while (inc_array(iter, dof_blue));
    free(iter);

    free(table_u);
    free(table_l);
    return ATTACK_FAIL;
}

/* 
 * Theoretical full attack, only for illustration:
 * impractical complexity, might not work due to data size limitations.
 * Input is 32-byte target t, stores 160-byte message (including padding) in m.
 * Returns zero if attack is successful.
 */
int full_attack(unsigned char *m, const unsigned char *t)
{
    unsigned char m1[32], m5[32], x[32], zero[16];

    // C standard random library is not guaranteed to be good
    // Doesn't matter, we won't use this anyway
    srand((unsigned int)time(NULL));

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
