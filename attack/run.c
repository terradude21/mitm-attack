#include <stdio.h>

#include "aes.h"
#include "attack.h"
#include "haraka.h"

/*
unsigned char in[16] = {
    0xf2, 0x0a, 0x22, 0x5c, 
    0x01, 0x01, 0x01, 0x01,
    0xc6, 0xc6, 0xc6, 0xc6,
    0xd4, 0xd4, 0xd4, 0xd5
};
*/

/*
 * After mixcol:
 * 9f dc 58 9d
 * 01 01 01 01
 * c6 c6 c6 c6
 * d5 d5 d7 d6
 */

int main()
{
    /* unsigned char s[64];

    for (int i = 0; i < 64; i++)
        s[i] = i;

    haraka512_p(s, s);

    for (int i = 0; i < 64; i++) {
        printf("%.2hhx ", s[i]);
    }

    printf("\n");

    haraka512_p_inv(s, s);

    for (int i = 0; i < 64; i++) {
        printf("%.2hhx ", s[i]);
    } */

    /* unsigned char a[2] = {0, 0};
    do {
        printf("%.2hhx %.2hhx\n", a[0], a[1]);
    } while (inc_array(a, 2)); */
}
