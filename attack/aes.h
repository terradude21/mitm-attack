#ifndef AES_H
#define AES_H

#include <stdint.h>

void aes_addkey(unsigned char *a, const uint64_t k0, const uint64_t k1);
void aes_subbyte(unsigned char *a, const unsigned char *sbox);
void aes_shiftrow(unsigned char *a, const int inv);
void aes_mixcol(unsigned char *a);
void aes_mixcol_inv(unsigned char *a);

void aes(unsigned char *a, const uint64_t k0, const uint64_t k1);
void aes_inv(unsigned char *a, const uint64_t k0, const uint64_t k1);

#endif
