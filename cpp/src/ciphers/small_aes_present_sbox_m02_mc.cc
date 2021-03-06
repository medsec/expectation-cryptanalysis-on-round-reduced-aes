/**
 * Implementation of Small-AES with nibbles and the PRESENT S-box
 * Do NOT use for any production purpose. No guarantees are given for anything.
 *
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

// ---------------------------------------------------------------------

#include <stdint.h>

#include "ciphers/small_aes_present_sbox_m02_mc.h"
#include "utils/utils.h"

// ---------------------------------------------------------------------

namespace ciphers {

    // ---------------------------------------------------------------------

    __m128i small_aes_present_sbox_m02_mc_mix_columns(__m128i state) {
        // x_2, x_3, x_0, x_1, x_6, x_7, x_4, x_5,
        // x_10, x_11, x_8, x_9, x_14, x_15, x_12, x_13
        const __m128i c = vshuffle(
            state,
            vsetr8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13)
        );

        // x_3, x_0, x_1, x_2, x_7, x_4, x_5, x_6,
        const __m128i d = vshuffle(
            state,
            vsetr8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14)
        );

        // y = 2 * (c + d) = 2 *
        // ( x_2 xor  x_3,  x_3 xor  x_0,  x_0 +  x_1,  x_1 +  x_2,
        //   x_6 xor  x_7,  x_7 xor  x_4,  x_4 +  x_5,  x_5 +  x_6,
        //  x_10 xor x_11, x_11 xor  x_8,  x_8 +  x_9,  x_9 + x_10,
        //  x_14 xor x_15, x_15 xor x_12, x_12 + x_13, x_13 + x_14)
        const __m128i y = vshuffle(SMALL_AES_TIMES_TWO, vxor(c, d));

        // 2x_0, 2x_1, 2x_2, 2x_3, ...
        const __m128i z = state;

        // 3x_0, 3x_1, 3x_2, 3x_3, ...
        const __m128i e = vshuffle(SMALL_AES_TIMES_THREE, state);

        // 3x_1, 3x_2, 3x_3, 3x_0, ...
        const __m128i f = vshuffle(
            e,
            vsetr8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12)
        );

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

    __m128i small_aes_present_sbox_m02_mc_sub_bytes(__m128i state) {
        return vshuffle(SMALL_AES_PRESENT_SBOX, state);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_present_sbox_m02_mc_encrypt_round(
        __m128i state,
        const __m128i round_key) {
        state = small_aes_present_sbox_m02_mc_sub_bytes(state);
        state = small_aes_shift_rows(state);
        state = small_aes_present_sbox_m02_mc_mix_columns(state);
        return vxor(state, round_key);
    }

    // ---------------------------------------------------------------------

    void small_aes_present_sbox_m02_mc_encrypt_rounds_only_sbox_in_final(
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
            state = small_aes_present_sbox_m02_mc_encrypt_round(
                state,
                ctx->key[i]
            );
        }

        state = small_aes_present_sbox_m02_mc_sub_bytes(state);
        state = vxor(state, ctx->key[num_rounds]);

        to_byte_array(ciphertext, state);
    }

    // ---------------------------------------------------------------------

    __m128i
    small_aes_present_sbox_m02_mc_encrypt_rounds_only_sbox_in_final_with_aes_ni(
        const small_aes_ctx_t *ctx,
        __m128i plaintext,
        const size_t num_rounds) {

        if (num_rounds > SMALL_AES_NUM_ROUNDS) {
            return plaintext;
        }

        __m128i state = vxor(plaintext, ctx->key[0]);

        for (size_t i = 1; i < num_rounds; ++i) {
            state = small_aes_present_sbox_m02_mc_encrypt_round(
                state,
                ctx->key[i]
            );
        }

        state = small_aes_present_sbox_m02_mc_sub_bytes(state);
        return vxor(state, ctx->key[num_rounds]);
    }

    // ---------------------------------------------------------------------

    void
    small_aes_present_sbox_m02_mc_encrypt_rounds_always_mc(
        const small_aes_ctx_t *ctx,
        const small_aes_state_t plaintext,
        small_aes_state_t ciphertext,
        size_t num_rounds) {
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
            state = small_aes_present_sbox_m02_mc_encrypt_round(state, keys[i]);
        }

        to_byte_array(ciphertext, state);
    }

}
