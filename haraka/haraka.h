#ifndef HARAKA_H
#define HARAKA_H

void init_rc();
void seed_rc(const unsigned char *seed, size_t seedlen);

void haraka512_p(unsigned char *out, const unsigned char *in);
void haraka512(unsigned char *out, const unsigned char *in);
void haraka_s(unsigned char *out, size_t outlen, const unsigned char *in, size_t inlen);

#endif
