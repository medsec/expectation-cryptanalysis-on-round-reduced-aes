#ifndef _SMALL_SBOXES_H_
#define _SMALL_SBOXES_H_

#define _X1    vsetr8(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f)
#define _X2    vsetr8(0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x03, 0x01, 0x07, 0x05, 0x0b, 0x09, 0x0f, 0x0d)
#define _X3    vsetr8(0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02)

#define _IDENTITY_SBOX vsetr8(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f)

// See https://eprint.iacr.org/2015/433.pdf
// See https://link.springer.com/content/pdf/10.1007%2F978-3-662-48116-5_24.pdf
#define _4_BIT_OPTIMAL_SBOX_0   vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 11, 12, 9, 3, 14, 10, 5)
#define _4_BIT_OPTIMAL_SBOX_1   vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 11, 14, 3, 5, 9, 10, 12)
#define _4_BIT_OPTIMAL_SBOX_2   vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 11, 14, 3, 10, 12, 5, 9)
#define _4_BIT_OPTIMAL_SBOX_3   vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 12, 5, 3, 10, 14, 11, 9)
#define _4_BIT_OPTIMAL_SBOX_4   vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 12, 9, 11, 10, 14, 5, 3)
#define _4_BIT_OPTIMAL_SBOX_5   vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 12, 11, 9, 10, 14, 3, 5)
#define _4_BIT_OPTIMAL_SBOX_6   vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 12, 11, 9, 10, 14, 5, 3)
#define _4_BIT_OPTIMAL_SBOX_7   vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 12, 14, 11, 10, 9, 3, 5)
#define _4_BIT_OPTIMAL_SBOX_8   vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 14, 9, 5, 10, 11, 3, 12)
#define _4_BIT_OPTIMAL_SBOX_9   vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 14, 11, 3, 5, 9, 10, 12)
#define _4_BIT_OPTIMAL_SBOX_10  vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 14, 11, 5, 10, 9, 3, 12)
#define _4_BIT_OPTIMAL_SBOX_11  vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 14, 11, 10, 5, 9, 12, 3)
#define _4_BIT_OPTIMAL_SBOX_12  vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 14, 11, 10, 9, 3, 12, 5)
#define _4_BIT_OPTIMAL_SBOX_13  vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 14, 12, 9, 5, 11, 10, 3)
#define _4_BIT_OPTIMAL_SBOX_14  vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 14, 12, 11, 3, 9, 5, 10)
#define _4_BIT_OPTIMAL_SBOX_15  vsetr8(0, 1, 2, 13, 4, 7, 15, 6, 8, 14, 12, 11, 9, 3, 10, 5)

#define _4_BIT_PLATINUM_SBOX_0_4_NUM_1_DL_CATEGORY_0    vsetr8(0, 11, 12, 5, 6, 1, 9, 10, 3, 14, 15, 8, 13, 4, 2, 7)
#define _4_BIT_PLATINUM_SBOX_0_4_NUM_1_DL_CATEGORY_1    vsetr8(0, 12, 13, 10, 5, 11, 14, 7, 15, 6, 2, 1, 3, 8, 9, 4)

#define _4_BIT_PLATINUM_SBOX_1_3_NUM_1_DL_CATEGORY_0    vsetr8(0, 12, 9, 7 ,6, 1, 15, 2, 3, 11, 4, 14, 13, 8, 10, 5)
#define _4_BIT_PLATINUM_SBOX_1_3_NUM_1_DL_CATEGORY_1    vsetr8(0, 12, 9, 7, 15, 2, 6, 1, 3, 11, 4, 14, 10, 5, 13, 8)
#define _4_BIT_PLATINUM_SBOX_1_3_NUM_1_DL_CATEGORY_2    vsetr8(0, 11, 8, 5, 15, 12, 3, 6, 14, 4, 7, 9, 2, 1, 13, 10)
#define _4_BIT_PLATINUM_SBOX_1_3_NUM_1_DL_CATEGORY_3    vsetr8(0, 13, 4, 11, 7, 14, 9, 2, 6, 10, 3, 5, 8, 1, 15, 12)

#define _4_BIT_PLATINUM_SBOX_2_2_NUM_1_DL_CATEGORY_0    vsetr8(0, 13, 8, 2, 14, 11, 7, 5, 15, 6, 3, 12, 4, 1, 9, 10)
#define _4_BIT_PLATINUM_SBOX_2_2_NUM_1_DL_CATEGORY_1    vsetr8(0, 11, 14, 1, 10, 7, 13, 4, 6, 12, 9, 15, 5, 8, 3, 2)
#define _4_BIT_PLATINUM_SBOX_2_2_NUM_1_DL_CATEGORY_2    vsetr8(0, 11, 6, 9, 12, 5, 3, 14, 13, 7, 8, 4, 2, 10, 15, 1)
#define _4_BIT_PLATINUM_SBOX_2_2_NUM_1_DL_CATEGORY_3    vsetr8(0, 14, 9, 5, 15, 8, 10, 7, 3, 11, 6, 12, 4, 1, 13, 2)

#endif // _SMALL_SBOXES_H_
