/**
 * Implementation Small-scale AES with nibbles. 
 * Uses SSE Instructions for performance, but uses only the low four bits
 * of each byte.
 * 
 * Do NOT use for any production purpose. No guarantees are given for anything.
 * 
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

// ---------------------------------------------------------------------

#include <emmintrin.h> // SSE2
#include <smmintrin.h> // SSE4.1
#include <tmmintrin.h> // SSSE3
#include <wmmintrin.h> // AES-NI
#include <stdint.h>

#include "ciphers/small_aes.h"
#include "utils/utils.h"

#include <stdio.h>

// ---------------------------------------------------------------------

namespace ciphers {

    static const uint8_t RCON[15] = {0x0, 0x1, 0x2, 0x4, 0x8, 0x3, 0x6, 0xc,
                                     0xb, 0x5, 0xa, 0x7, 0xe, 0xf, 0xd};

#define SMALL_AES_SBOX                  vsetr8(0x06, 0x0b, 0x05, 0x04, 0x02, 0x0e, 0x07, 0x0a, 0x09, 0x0d, 0x0f, 0x0c, 0x03, 0x01, 0x00, 0x08)
#define SMALL_AES_INVERSE_SBOX          vsetr8(0x0e, 0x0d, 0x04, 0x0c, 0x03, 0x02, 0x00, 0x06, 0x0f, 0x08, 0x07, 0x01, 0x0b, 0x09, 0x05, 0x0a)
#define SMALL_AES_RCON(round)           vsetr8(RCON[round], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
#define SMALL_AES_SHIFT_ROWS            vsetr8(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)
#define SMALL_AES_INVERSE_SHIFT_ROWS    vsetr8(0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3)
#define SMALL_AES_MIX_COLUMNS_MASK      vsetr8(0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10)

// Map M, such that AES-Sbox[M[x]] = SmallAES-Sbox[x]
#define SMALL_AES_TO_USUAL_AES_SBOX_MAP vsetr8((uint8_t)0xa5, (uint8_t)0x9e, (uint8_t)0x36, (uint8_t)0x30,\
                                               (uint8_t)0x6a, (uint8_t)0xd7, (uint8_t)0x38, (uint8_t)0xa3,\
                                               (uint8_t)0x40, (uint8_t)0xf3, (uint8_t)0xfb, (uint8_t)0x81,\
                                               (uint8_t)0xd5, (uint8_t)0x09, (uint8_t)0x52, (uint8_t)0xbf)

#define SMALL_AES_TIMES_TWO             vsetr8(0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x3, 0x1, 0x7, 0x5, 0xb, 0x9, 0xf, 0xd)
#define SMALL_AES_TIMES_THREE           vsetr8(0x0, 0x3, 0x6, 0x5, 0xc, 0xf, 0xa, 0x9, 0xb, 0x8, 0xd, 0xe, 0x7, 0x4, 0x1, 0x2)

#define SMALL_AES_TIMES_9               vsetr8(0x0, 0x9, 0x1, 0x8, 0x2, 0xb, 0x3, 0xa, 0x4, 0xd, 0x5, 0xc, 0x6, 0xf, 0x7, 0xe)
#define SMALL_AES_TIMES_11              vsetr8(0x0, 0xb, 0x5, 0xe, 0xa, 0x1, 0xf, 0x4, 0x7, 0xc, 0x2, 0x9, 0xd, 0x6, 0x8, 0x3)
#define SMALL_AES_TIMES_13              vsetr8(0x0, 0xd, 0x9, 0x4, 0x1, 0xc, 0x8, 0x5, 0x2, 0xf, 0xb, 0x6, 0x3, 0xe, 0xa, 0x7)
#define SMALL_AES_TIMES_14              vsetr8(0x0, 0xe, 0xf, 0x1, 0xd, 0x3, 0x2, 0xc, 0x9, 0x7, 0x6, 0x8, 0x4, 0xa, 0xb, 0x5)

#define LO_NIBBLES_MASK                 vset64(0x0F0F0F0F0F0F0F0FL, 0x0F0F0F0F0F0F0F0FL)
#define HI_NIBBLES_MASK                 vset64(0xF0F0F0F0F0F0F0F0L, 0xF0F0F0F0F0F0F0F0L)

    // ---------------------------------------------------------------------

    __m128i
    shuffle_for_hi_and_lo_nibbles(const __m128i sbox, const __m128i state) {
        __m128i x = vshuffle(
            sbox,
            vand(state, LO_NIBBLES_MASK)
        );
        __m128i y = vshuffle(
            sbox,
            vand(vshiftright16(state, 4), LO_NIBBLES_MASK)
        );
        return vor(x, vshiftleft16(y, 4));
    }

    // ---------------------------------------------------------------------

    /**
     * Given an 8-byte input, spreads the nibbles to 16 bytes.
     * @param input
     * @return
     */
    __m128i to_lower_nibbles(const small_aes_state_t input) {
        // K01, K23, K34, ...
        const __m128i x = vset8(
            0, 0, 0, 0,
            0, 0, 0, 0,
            input[7], input[6], input[5], input[4],
            input[3], input[2], input[1], input[0]
        );
        const __m128i mask = LO_NIBBLES_MASK;

        // K1, K3, K5, ...
        __m128i x_hi = vand(x, mask);
        const __m128i x_lo = vand(vshiftright16(x, 4), mask);
        // K0, K2, K4, ...
        x_hi = vand(x_hi, mask);
        return vunpacklo8(x_lo, x_hi);
    }

    // ---------------------------------------------------------------------

    /**
     * Given a sequence of two 8-byte plaintexts X = X[0], ..., X[7] and
     * Y = Y[0], ..., Y[7], considers them as 16-nibble entries
     * X* = X*[0], ..., X*[15] and Y* = Y*[0], ..., Y*[15],
     * distributes them and unpacks them nibblewise to
     * to Z = Y*[0] || X*[0], ..., Y*[15] || X*[15].
     * @param input Must contain at least 16 bytes.
     * @return Z.
     */
    __m128i to_nibbles(const uint8_t *input) {
        // K01, K23, K34, ...; L01, L23, L34, ...
        const __m128i x = vset8(
            0, 0, 0, 0,
            0, 0, 0, 0,
            input[7], input[6], input[5], input[4],
            input[3], input[2], input[1], input[0]
        );
        const __m128i y = vset8(
            0, 0, 0, 0,
            0, 0, 0, 0,
            input[15], input[14], input[13], input[12],
            input[11], input[10], input[9], input[8]
        );
        const __m128i x_mask = LO_NIBBLES_MASK;
        const __m128i y_mask = HI_NIBBLES_MASK;

        // K1, K3, ... K15; 0, 0, ... 0 in lower nibbles of the bytes
        __m128i x_hi = vand(x, x_mask);
        // L1, L3, ..., L15; 0, 0, ... 0 in upper nibbles of the bytes
        const __m128i y_hi = vand(vshiftleft16(y, 4), y_mask);

        // K0, K2, ... K14; 0, 0, ... 0 in lower nibbles of the bytes
        __m128i x_lo = vand(vshiftright16(x, 4), x_mask);
        // L0, L2, ..., L14; 0, 0, ... 0 in upper nibbles of the bytes
        const __m128i y_lo = vand(y, y_mask);

        x_hi = vand(x_hi, x_mask);

        // L0K0, L2K2, ... L2K14; 0, 0, ... 0 in bytes
        x_lo = vor(x_lo, y_lo);
        // L1K1, L3K3, ... L15K15; 0, 0, ... 0 in bytes
        x_hi = vor(x_hi, y_hi);
        return vunpacklo8(x_lo, x_hi);
    }

    // ---------------------------------------------------------------------

    void to_byte_array(small_aes_state_t output, const __m128i input) {
        // x0, x2, ..., x14; 0, ... 0
        __m128i evens = vshuffle(
            input,
            vsetr8(0, 2, 4, 6,
                   8, 10, 12, 14,
                   (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF,
                   (uint8_t) 0xFF,
                   (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF,
                   (uint8_t) 0xFF
            )
        );
        // x1, x3, ..., x15; 0, ... 0
        __m128i odds = vshuffle(
            input,
            vsetr8(1, 3, 5, 7,
                   9, 11, 13, 15,
                   (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF,
                   (uint8_t) 0xFF,
                   (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF,
                   (uint8_t) 0xFF
            )
        );
        // Shift evens to higher nibbles
        evens = vshiftleft16(evens, 4);

        uint8_t temp[16];
        storeu(temp, vxor(evens, odds));
        memcpy(output, temp, SMALL_AES_NUM_STATE_BYTES);
    }

    // ---------------------------------------------------------------------

    void to_byte_array_2(uint8_t output[16], __m128i input) {
        // x0, x2, ..., x14; 0, ..., 0
        __m128i x_evens = vshuffle(
            input,
            vsetr8(0, 2, 4, 6,
                   8, 10, 12, 14,
                   (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF,
                   (uint8_t) 0xFF,
                   (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF,
                   (uint8_t) 0xFF
            )
        );
        // y0, y2, ..., y14; 0, ..., 0
        __m128i y_evens = vshuffle(
            vand(input, HI_NIBBLES_MASK),
            vsetr8(
                (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF,
                (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF,
                0, 2, 4, 6, 8, 10, 12, 14
            )
        );
        // x1, x3, ..., x15; 0, ..., 0
        __m128i x_odds = vshuffle(input,
                                  vsetr8(1, 3, 5, 7,
                                         9, 11, 13, 15,
                                         (uint8_t) 0xFF, (uint8_t) 0xFF,
                                         (uint8_t) 0xFF, (uint8_t) 0xFF,
                                         (uint8_t) 0xFF, (uint8_t) 0xFF,
                                         (uint8_t) 0xFF, (uint8_t) 0xFF
                                  )
        );
        // y1, y3, ..., y15; 0, ..., 0
        __m128i y_odds = vshuffle(
            vand(input, HI_NIBBLES_MASK),
            vsetr8((uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF,
                   (uint8_t) 0xFF,
                   (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF,
                   (uint8_t) 0xFF,
                   1, 3, 5, 7, 9, 11, 13, 15
            )
        );

        // Shift evens to higher nibbles
        x_evens = vshiftleft16(vand(x_evens, LO_NIBBLES_MASK), 4);
        y_odds = vshiftright16(y_odds, 4);  // Shift odds to lower nibbles
        x_odds = vand(x_odds, LO_NIBBLES_MASK);

        const __m128i value = vxor(vxor(x_evens, x_odds),
                                   vxor(y_evens, y_odds));
        storeu(output, value);
    }

    // ---------------------------------------------------------------------

    void to_byte_array_4(uint8_t output[32], __m256i input) {
        to_byte_array_2(output, vget128(input, 0));
        to_byte_array_2(output + 16, vget128(input, 1));
    }

    // ---------------------------------------------------------------------

    __m128i generate_round_key(__m128i k, const size_t round) {
        __m128i col0 = small_aes_sub_bytes(k);

        // rotate the last column and put it to the front column
        __m128i mask = vset8(
            (uint8_t) 0xff, (uint8_t) 0xff, (uint8_t) 0xff, (uint8_t) 0xff,
            (uint8_t) 0xff, (uint8_t) 0xff, (uint8_t) 0xff,
            (uint8_t) 0xff, (uint8_t) 0xff, (uint8_t) 0xff, (uint8_t) 0xff,
            (uint8_t) 0xff, 12, 15, 14, 13
        );
        col0 = vshuffle(col0, mask); // [S(12), S(15), S(14), S(13), 0, ..., 0]
        col0 = vxor(SMALL_AES_RCON(round), col0);
        col0 = vand(
            vxor(k, col0),
            vset32(0xFFFFFFFF, 0, 0, 0)
        ); // col0 contains the first correct column

        __m128i col1 = vand(vxor(vshiftleft_bytes(col0, 4), k),
                            vset32(0, 0xFFFFFFFF, 0, 0));
        __m128i col2 = vand(vxor(vshiftleft_bytes(col1, 4), k),
                            vset32(0, 0, 0xFFFFFFFF, 0));
        __m128i col3 = vand(vxor(vshiftleft_bytes(col2, 4), k),
                            vset32(0, 0, 0, 0xFFFFFFFF));
        return vxor(vxor(col0, col1), vxor(col2, col3));
    }

    // ---------------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------------

    void small_aes_decrypt(const small_aes_ctx_t *ctx,
                           const small_aes_state_t ciphertext,
                           small_aes_state_t plaintext) {
        __m128i state = to_lower_nibbles(ciphertext);
        const __m128i *keys = ctx->key;

        state = small_aes_decrypt_last_round(state, keys[SMALL_AES_NUM_ROUNDS]);

        for (size_t i = 1; i < SMALL_AES_NUM_ROUNDS; ++i) {
            state = small_aes_decrypt_round(state,
                                            keys[SMALL_AES_NUM_ROUNDS - i]);
        }

        state = vxor(state, keys[0]);
        to_byte_array(plaintext, state);
    }

    // ---------------------------------------------------------------------

    void small_aes_encrypt(const small_aes_ctx_t *ctx,
                           const small_aes_state_t plaintext,
                           small_aes_state_t ciphertext) {
        __m128i state = to_lower_nibbles(plaintext);
        const __m128i *keys = ctx->key;
        state = vxor(state, keys[0]);

        for (size_t i = 1; i < SMALL_AES_NUM_ROUNDS; ++i) {
            state = small_aes_encrypt_round(state, keys[i]);
        }

        state = small_aes_encrypt_last_round(state, keys[SMALL_AES_NUM_ROUNDS]);
        to_byte_array(ciphertext, state);
    }

    // ---------------------------------------------------------------------

    void small_aes_encrypt_rounds(const small_aes_ctx_t *ctx,
                                  const small_aes_state_t plaintext,
                                  small_aes_state_t ciphertext,
                                  const size_t num_rounds) {
        if (num_rounds > SMALL_AES_NUM_ROUNDS) {
            return;
        }

        __m128i state = to_lower_nibbles(plaintext);
        const __m128i *keys = ctx->key;

        state = vxor(state, keys[0]);

        for (size_t i = 1; i < num_rounds; ++i) {
            state = small_aes_encrypt_round(state, keys[i]);
        }

        state = small_aes_encrypt_last_round(state, keys[num_rounds]);
        to_byte_array(ciphertext, state);
    }

    // ---------------------------------------------------------------------

    void small_aes_encrypt_rounds_always_mc(const small_aes_ctx_t *ctx,
                                            const small_aes_state_t plaintext,
                                            small_aes_state_t ciphertext,
                                            const size_t num_rounds) {
        if (num_rounds > SMALL_AES_NUM_ROUNDS) {
            return;
        }

        if (num_rounds == 0) {
            memcpy(ciphertext, plaintext, SMALL_AES_NUM_STATE_BYTES);
            return;
        }

        __m128i state = to_lower_nibbles(plaintext);
        const __m128i *keys = ctx->key;

        state = vxor(state, keys[0]);

        for (size_t i = 1; i <= num_rounds; ++i) {
            state = small_aes_encrypt_round(state, keys[i]);
        }

        to_byte_array(ciphertext, state);
    }

    // ---------------------------------------------------------------------

    void small_aes_encrypt_rounds_only_sbox_in_final(
        const small_aes_ctx_t *ctx,
        const small_aes_state_t plaintext,
        small_aes_state_t ciphertext,
        const size_t num_rounds) {

        if (num_rounds > SMALL_AES_NUM_ROUNDS) {
            return;
        }

        __m128i state = to_lower_nibbles(plaintext);
        state = vxor(state, ctx->key[0]);

        for (size_t i = 1; i < num_rounds; ++i) {
            state = small_aes_encrypt_round(state, ctx->key[i]);
        }

        state = small_aes_sub_bytes(state);
        state = vxor(state, ctx->key[num_rounds]);

        to_byte_array(ciphertext, state);
    }

    // ---------------------------------------------------------------------

    /**
     * @param state [15, 14, ..., 0]
     * State after being processed by an AES round. Assumes that Byte i contains
     * the value of the current SmallAES state in its low nibble.
     *
     * The AES round performs MC in GF(2^8), we need reduction in GF(2^4) with
     * x^4 + x + 1. So, the nibbles that need reduction have a high Bit at
     * the position that represents 2^4: b = 0001 ????
     *
     * So, we need to shift them twice:
     * mask = (b & 0x10)
     * b = b xor mask xor (mask >> 4) xor (mask >> 3);
     *
     * or alternatively:
     * mask = (b << 3) & 0x80
     * b = vblend8(0, 0x13, mask) xor b
     * @return
     */
    __m128i small_aes_correct_mix_columns(__m128i state) {
        const __m128i mask = vand(state, SMALL_AES_MIX_COLUMNS_MASK);
        state = vxor(state, mask);
        state = vxor(state, vshiftright16(mask, 3));
        return vxor(state, vshiftright16(mask, 4));
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_encrypt_round_with_aes_ni(__m128i state,
                                                const __m128i round_key) {
        state = vshuffle(SMALL_AES_TO_USUAL_AES_SBOX_MAP, state);
        state = aesenc(state, round_key);
        return small_aes_correct_mix_columns(state);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_encrypt_rounds_only_sbox_in_final_with_aes_ni(
        const small_aes_ctx_t *ctx,
        const __m128i plaintext,
        const size_t num_rounds) {

        __m128i state = vxor(plaintext, ctx->key[0]);

        for (size_t i = 1; i < num_rounds; ++i) {
            state = small_aes_encrypt_round_with_aes_ni(state, ctx->key[i]);
        }

        state = small_aes_sub_bytes(state);
        return vxor(state, ctx->key[num_rounds]);
    }

    // ---------------------------------------------------------------------

    void small_aes_key_setup(small_aes_ctx_t *ctx, const small_aes_key_t key) {
        ctx->key[0] = to_lower_nibbles(key);

        for (size_t i = 1; i < SMALL_AES_NUM_ROUND_KEYS; ++i) {
            ctx->key[i] = generate_round_key(ctx->key[i - 1], i);
        }
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_encrypt_round(__m128i state, const __m128i round_key) {
        state = small_aes_sub_bytes(state);
        state = small_aes_shift_rows(state);
        state = small_aes_mix_columns(state);
        return vxor(state, round_key);
    }

    // ---------------------------------------------------------------------

    __m128i
    small_aes_encrypt_last_round(__m128i state, const __m128i round_key) {
        state = small_aes_sub_bytes(state);
        state = small_aes_shift_rows(state);
        return vxor(state, round_key);
    }

    // ---------------------------------------------------------------------

    __m128i
    small_aes_decrypt_last_round(__m128i state, const __m128i round_key) {
        state = vxor(state, round_key);
        state = small_aes_invert_shift_rows(state);
        return small_aes_invert_sub_bytes(state);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_decrypt_round(__m128i state, const __m128i round_key) {
        state = vxor(state, round_key);
        state = small_aes_invert_mix_columns(state);
        state = small_aes_invert_shift_rows(state);
        return small_aes_invert_sub_bytes(state);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_shift_rows(__m128i state) {
        return vshuffle(state, SMALL_AES_SHIFT_ROWS);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_invert_shift_rows(__m128i state) {
        return vshuffle(state, SMALL_AES_INVERSE_SHIFT_ROWS);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_sub_bytes(__m128i state) {
        return vshuffle(SMALL_AES_SBOX, state);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_invert_sub_bytes(__m128i state) {
        return vshuffle(SMALL_AES_INVERSE_SBOX, state);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_mix_columns(__m128i state) {
        // x_2, x_3, x_0, x_1, x_6, x_7, x_4, x_5,
        // x_10, x_11, x_8, x_9, x_14, x_15, x_12, x_13
        const __m128i c = vshuffle(state,
                                   vsetr8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9,
                                          14, 15, 12, 13));

        // x_3, x_0, x_1, x_2, x_7, x_4, x_5, x_6,
        const __m128i d = vshuffle(state,
                                   vsetr8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10,
                                          15, 12, 13, 14));

        // x_2 xor x_3, x_0 xor x_3, x_0 xor x_1, x_1 xor x_2, ...
        const __m128i y = vxor(c, d);

        // 2x_0, 2x_1, 2x_2, 2x_3, ...
        const __m128i z = vshuffle(SMALL_AES_TIMES_TWO, state);

        // 3x_0, 3x_1, 3x_2, 3x_3, ...
        const __m128i e = vshuffle(SMALL_AES_TIMES_THREE, state);

        // 3x_1, 3x_2, 3x_3, 3x_0, ...
        const __m128i f = vshuffle(e,
                                   vsetr8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8,
                                          13, 14, 15, 12));

        // 3x_1 xor x_2 xor x_3,
        // x_0 xor 3x_2 xor x_3
        // x_0 xor x_1 xor 3x_3
        // 3x_0 xor x_1 xor x_2
        const __m128i b = vxor(y, f);

        // 2x_0 xor 3x_1 xor x_2 xor x_3,
        // x_0 xor 2x_1 xor 3x_2 xor x_3,
        // x_0 xor x_1 xor 2x_2 xor 3x_3,
        // 3x_0 xor x_1 xor x_2 xor 2x_3, ...
        return vxor(b, z);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_invert_mix_columns(__m128i state) {
        // At the end, we want for each i:
        // result[i] = 14 * state[j1] + 11 * state[j2] +
        //             13 * state[j2] + 9 * state[j3]
        // Here, we shuffle the state 4 x so that we only have to multiply the
        // shuffled states by 14, 11, 13, and 9 and XOR them.

        // Shuffles the state so that the result[i].
        const __m128i times_9 = vshuffle(state,
                                         vsetr8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8,
                                                9, 10, 15, 12, 13, 14));
        const __m128i times_11 = vshuffle(state,
                                          vsetr8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10,
                                                 11, 8, 13, 14, 15, 12));
        const __m128i times_13 = vshuffle(state,
                                          vsetr8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11,
                                                 8, 9, 14, 15, 12, 13));

        const __m128i results_times_9 = vshuffle(SMALL_AES_TIMES_9, times_9);
        const __m128i results_times_11 = vshuffle(SMALL_AES_TIMES_11, times_11);
        const __m128i results_times_13 = vshuffle(SMALL_AES_TIMES_13, times_13);
        const __m128i results_times_14 = vshuffle(SMALL_AES_TIMES_14, state);

        return vxor(
            vxor(results_times_9, results_times_11),
            vxor(results_times_13, results_times_14)
        );
    }

    // ---------------------------------------------------------------------
    // Methods for 2 blocks simultaneously
    // ---------------------------------------------------------------------

    void small_aes_encrypt_2(const small_aes_ctx_t *ctx,
                             const uint8_t *plaintexts,
                             uint8_t *ciphertexts) {
        small_aes_encrypt_rounds_2(ctx,
                                   plaintexts,
                                   ciphertexts,
                                   SMALL_AES_NUM_ROUNDS);
    }

    // ---------------------------------------------------------------------

    /**
     * Encrypts two plaintexts in parallel.
     * @param ctx
     * @param plaintexts Provides at least 16 bytes.
     * @param ciphertexts Provides at least 16 bytes.
     * @param num_rounds Non-negative integer.
     */
    void small_aes_encrypt_rounds_2(const small_aes_ctx_t *ctx,
                                    const uint8_t *plaintexts,
                                    uint8_t *ciphertexts,
                                    size_t num_rounds) {
        if (num_rounds > SMALL_AES_NUM_ROUNDS) {
            return;
        }

        __m128i state = to_nibbles(plaintexts);

        const __m128i *keys = ctx->key_2;
        state = vxor(state, keys[0]);

        for (size_t i = 1; i < num_rounds; ++i) {
            state = small_aes_encrypt_round_2(state, keys[i]);
        }

        state = small_aes_encrypt_last_round_2(state, keys[num_rounds]);
        to_byte_array_2(ciphertexts, state);
    }

    // ---------------------------------------------------------------------

    void small_aes_key_setup_2(small_aes_ctx_t *ctx) {
        __m128i *k = ctx->key;
        __m128i *k2 = ctx->key_2;

        for (size_t i = 0; i < SMALL_AES_NUM_ROUND_KEYS; ++i) {
            k2[i] = vor(k[i], vand(vshiftleft16(k[i], 4), HI_NIBBLES_MASK));
        }
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_encrypt_round_2(__m128i state, const __m128i round_key) {
        state = small_aes_sub_bytes_2(state);
        state = small_aes_shift_rows_2(state);
        state = small_aes_mix_columns_2(state);
        return vxor(state, round_key);
    }

    // ---------------------------------------------------------------------

    __m128i
    small_aes_encrypt_last_round_2(__m128i state, const __m128i round_key) {
        state = small_aes_sub_bytes_2(state);
        state = small_aes_shift_rows_2(state);
        return vxor(state, round_key);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_shift_rows_2(__m128i state) {
        return vshuffle(state, SMALL_AES_SHIFT_ROWS);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_sub_bytes_2(__m128i state) {
        return shuffle_for_hi_and_lo_nibbles(SMALL_AES_SBOX, state);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_mix_columns_2(__m128i state) {
        // x_2, x_3, x_0, x_1, x_6, x_7, x_4, x_5,
        // x_10, x_11, x_8, x_9, x_14, x_15, x_12, x_13
        const __m128i c = vshuffle(state,
                                   vsetr8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9,
                                          14, 15, 12, 13));

        // x_3, x_0, x_1, x_2, x_7, x_4, x_5, x_6,
        const __m128i d = vshuffle(state,
                                   vsetr8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10,
                                          15, 12, 13, 14));

        // x_2 xor x_3, x_0 xor x_3, x_0 xor x_1, x_1 xor x_2, ...
        const __m128i y = vxor(c, d);

        // 2x_0, 2x_1, 2x_2, 2x_3, ...
        const __m128i z = shuffle_for_hi_and_lo_nibbles(
            SMALL_AES_TIMES_TWO, state
        );

        // 3x_0, 3x_1, 3x_2, 3x_3, ...
        const __m128i e = shuffle_for_hi_and_lo_nibbles(
            SMALL_AES_TIMES_THREE, state
        );

        // 3x_1, 3x_2, 3x_3, 3x_0, ...
        const __m128i f = vshuffle(e,
                                   vsetr8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8,
                                          13, 14, 15, 12));

        // 3x_1 xor x_2 xor x_3,
        // x_0 xor 3x_2 xor x_3
        // x_0 xor x_1 xor 3x_3
        // 3x_0 xor x_1 xor x_2
        const __m128i b = vxor(y, f);

        // 2x_0 xor 3x_1 xor x_2 xor x_3,
        // x_0 xor 2x_1 xor 3x_2 xor x_3,
        // x_0 xor x_1 xor 2x_2 xor 3x_3,
        // 3x_0 xor x_1 xor x_2 xor 2x_3, ...
        return vxor(b, z);
    }

    // ---------------------------------------------------------------------
    // Methods for 4 blocks simultaneously
    // ---------------------------------------------------------------------

    void small_aes_encrypt_4(const small_aes_ctx_t *ctx,
                             const uint8_t *plaintexts,
                             uint8_t *ciphertexts) {
        small_aes_encrypt_rounds_4(ctx,
                                   plaintexts,
                                   ciphertexts,
                                   SMALL_AES_NUM_ROUNDS);
    }

    // ---------------------------------------------------------------------

    /**
     * Encrypts four plaintexts in parallel.
     * @param ctx
     * @param plaintexts Provides at least 32 bytes.
     * @param ciphertexts Provides at least 32 bytes.
     * @param num_rounds Non-negative integer.
     */
    void small_aes_encrypt_rounds_4(const small_aes_ctx_t *ctx,
                                    const uint8_t *plaintexts,
                                    uint8_t *ciphertexts,
                                    size_t num_rounds) {
        if (num_rounds > SMALL_AES_NUM_ROUNDS) {
            return;
        }

        __m256i state = vset128(to_nibbles(plaintexts),
                                to_nibbles(plaintexts + 16));

        const __m256i *keys = ctx->key_4;
        state = avxxor(state, keys[0]);

        for (size_t i = 1; i < num_rounds; ++i) {
            state = small_aes_encrypt_round_4(state, keys[i]);
        }

        state = small_aes_encrypt_last_round_4(state, keys[num_rounds]);
        to_byte_array_4(ciphertexts, state);
    }

    // ---------------------------------------------------------------------

    void
    small_aes_encrypt_rounds_4_only_sbox_in_final(const small_aes_ctx_t *ctx,
                                                  const uint8_t *plaintexts,
                                                  uint8_t *ciphertexts,
                                                  size_t num_rounds) {
        if (num_rounds > SMALL_AES_NUM_ROUNDS) {
            return;
        }

        __m256i state = vset128(to_nibbles(plaintexts),
                                to_nibbles(plaintexts + 16));

        const __m256i *keys = ctx->key_4;
        state = avxxor(state, keys[0]);

        for (size_t i = 1; i < num_rounds; ++i) {
            state = small_aes_encrypt_round_4(state, keys[i]);
        }

        state = small_aes_sub_bytes_4(state);
        state = avxxor(state, keys[num_rounds]);
        to_byte_array_4(ciphertexts, state);
    }

    // ---------------------------------------------------------------------

    void small_aes_key_setup_4(small_aes_ctx_t *ctx) {
        __m128i *k = ctx->key;
        __m128i *k2 = ctx->key_2;
        __m256i *k4 = ctx->key_4;

        for (size_t i = 0; i < SMALL_AES_NUM_ROUND_KEYS; ++i) {
            k2[i] = vor(k[i], vand(vshiftleft16(k[i], 4), HI_NIBBLES_MASK));
            k4[i] = vset128(k2[i], k2[i]);
        }
    }

    // ---------------------------------------------------------------------

    __m256i small_aes_encrypt_round_4(__m256i state, const __m256i round_key) {
        state = small_aes_sub_bytes_4(state);
        state = small_aes_shift_rows_4(state);
        state = small_aes_mix_columns_4(state);
        return avxxor(state, round_key);
    }

    // ---------------------------------------------------------------------

    __m256i
    small_aes_encrypt_last_round_4(__m256i state, const __m256i round_key) {
        state = small_aes_sub_bytes_4(state);
        state = small_aes_shift_rows_4(state);
        return avxxor(state, round_key);
    }

    // ---------------------------------------------------------------------

    __m256i small_aes_shift_rows_4(__m256i state) {
        return avxshuffle(
            state,
            vset128(SMALL_AES_SHIFT_ROWS, SMALL_AES_SHIFT_ROWS)
        );
    }

    // ---------------------------------------------------------------------

    __m256i small_aes_sub_bytes_4(__m256i state) {
        return vset128(
            shuffle_for_hi_and_lo_nibbles(SMALL_AES_SBOX, vget128(state, 0)),
            shuffle_for_hi_and_lo_nibbles(SMALL_AES_SBOX, vget128(state, 1))
        );
    }

    // ---------------------------------------------------------------------

    __m256i small_aes_mix_columns_4(__m256i state) {
        // x_2, x_3, x_0, x_1, x_6, x_7, x_4, x_5,
        // x_10, x_11, x_8, x_9, x_14, x_15, x_12, x_13
        const __m256i c = avxshuffle(
            state,
            vset128(
                vsetr8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13),
                vsetr8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13)
            )
        );

        // x_3, x_0, x_1, x_2, x_7, x_4, x_5, x_6,
        const __m256i d = avxshuffle(
            state,
            vset128(
                vsetr8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14),
                vsetr8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14)
            )
        );

        // x_2 xor x_3, x_0 xor x_3, x_0 xor x_1, x_1 xor x_2, ...
        const __m256i y = avxxor(c, d);

        // 2x_0, 2x_1, 2x_2, 2x_3, ...
        const __m256i z = vset128(
            shuffle_for_hi_and_lo_nibbles(SMALL_AES_TIMES_TWO,
                                          vget128(state, 0)),
            shuffle_for_hi_and_lo_nibbles(SMALL_AES_TIMES_TWO,
                                          vget128(state, 1))
        );

        // 3x_0, 3x_1, 3x_2, 3x_3, ...
        const __m256i e = vset128(
            shuffle_for_hi_and_lo_nibbles(SMALL_AES_TIMES_THREE,
                                          vget128(state, 0)),
            shuffle_for_hi_and_lo_nibbles(SMALL_AES_TIMES_THREE,
                                          vget128(state, 1))
        );

        // 3x_1, 3x_2, 3x_3, 3x_0, ...
        const __m256i f = avxshuffle(
            e,
            vset128(
                vsetr8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12),
                vsetr8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12)
            )
        );

        // 3x_1 xor x_2 xor x_3,
        // x_0 xor 3x_2 xor x_3
        // x_0 xor x_1 xor 3x_3
        // 3x_0 xor x_1 xor x_2
        const __m256i b = avxxor(y, f);

        // 2x_0 xor 3x_1 xor x_2 xor x_3,
        // x_0 xor 2x_1 xor 3x_2 xor x_3,
        // x_0 xor x_1 xor 2x_2 xor 3x_3,
        // 3x_0 xor x_1 xor x_2 xor 2x_3, ...
        return avxxor(b, z);
    }

}
