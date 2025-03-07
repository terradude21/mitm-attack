#ifndef ATTACK_H
#define ATTACK_H

#define ATTACK_SUCCESS 0
#define ATTACK_FAIL -1

extern const int rf_index[12];
extern const int bf_index[12];
extern const int rb_index[12];
extern const int bb_index[12];

int attack(unsigned char *m, const unsigned char *m1, const unsigned char *m5,
    const unsigned char *rf, const unsigned char *bf, const unsigned char *ff,
    const unsigned char *rb, const unsigned char *bb, const unsigned char *fb,
    const int dof_red, const int dof_blue, const unsigned char *z, const unsigned char *x,
    const unsigned char *t);
int full_attack(unsigned char *m, const unsigned char *t);

#endif
