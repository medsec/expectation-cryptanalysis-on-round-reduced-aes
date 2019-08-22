/**
 * Implementation of Small-AES with nibbles and the TOY10 S-box.
 * Do NOT use for any production purpose. No guarantees are given for anything.
 *
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

// ---------------------------------------------------------------------

#include <stdint.h>

#include "ciphers/small_aes_toy10_sbox.h"
#include "utils/utils.h"

// ---------------------------------------------------------------------

namespace ciphers {

    __m128i small_aes_toy10_sbox_sub_bytes(__m128i state) {
        return vshuffle(SMALL_AES_TOY10_SBOX, state);
    }

    // ---------------------------------------------------------------------

    __m128i small_aes_toy10_sbox_encrypt_round(__m128i state,
                                               const __m128i round_key) {
        state = small_aes_toy10_sbox_sub_bytes(state);
        state = small_aes_shift_rows(state);
        state = small_aes_mix_columns(state);
        return vxor(state, round_key);
    }

    // ---------------------------------------------------------------------

    void small_aes_toy10_sbox_encrypt_rounds_only_sbox_in_final(
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
            state = small_aes_toy10_sbox_encrypt_round(state, ctx->key[i]);
        }

        state = small_aes_toy10_sbox_sub_bytes(state);
        state = vxor(state, ctx->key[num_rounds]);

        to_byte_array(ciphertext, state);
    }

    // ---------------------------------------------------------------------

    __m128i
    small_aes_toy10_sbox_encrypt_rounds_only_sbox_in_final_with_aes_ni(
        const small_aes_ctx_t *ctx,
        __m128i plaintext,
        const size_t num_rounds) {

        __m128i state = vxor(plaintext, ctx->key[0]);

        for (size_t i = 1; i < num_rounds; ++i) {
            state = small_aes_toy10_sbox_encrypt_round(state, ctx->key[i]);
        }

        state = small_aes_toy10_sbox_sub_bytes(state);
        return vxor(state, ctx->key[num_rounds]);
    }

    // ---------------------------------------------------------------------

    void
    small_aes_toy10_sbox_encrypt_rounds_always_mc(const small_aes_ctx_t *ctx,
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
            state = small_aes_toy10_sbox_encrypt_round(state, keys[i]);
        }

        to_byte_array(ciphertext, state);
    }

}
