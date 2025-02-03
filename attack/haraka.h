#ifndef HARAKA_H
#define HARAKA_H

extern const uint64_t haraka_rc[64];

void mix(unsigned char *s, const int *p);
void haraka512_p(unsigned char *out, const unsigned char *in);
void haraka512_p_inv(unsigned char *out, const unsigned char *in);
void haraka_s(unsigned char *out, size_t outlen, const unsigned char *in, size_t inlen);

#endif
