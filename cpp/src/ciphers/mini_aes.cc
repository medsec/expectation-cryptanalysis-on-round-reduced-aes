/**
 * Implementation Mini AES with 3-bit S-boxes.
 *
 * Do NOT use for any production purpose. No guarantees are given for anything.
 *
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

// ---------------------------------------------------------------------

#include <assert.h>
#include <stdint.h>

#include "ciphers/mini_aes.h"
#include "utils/utils.h"

#include <stdio.h>

// ---------------------------------------------------------------------

namespace ciphers {

    static void to_internal_state(mini_aes_internal_state_t target,
                                  const mini_aes_state_t state) {
        // 00011122 23334445 55666777 888999aa abbbcccd ddeeefff
        // becomes
        // 000 111 222 333 ... fff

        target[0] = (uint8_t)((state[0] >> 5) & 0x7);
        target[1] = (uint8_t)((state[0] >> 2) & 0x7);
        target[2] = (uint8_t)((state[0] << 1) & 0x6)
            | (uint8_t)((state[1] >> 7) & 0x1);
        target[3] = (uint8_t)((state[1] >> 4) & 0x7);

        target[4] = (uint8_t)((state[1] >> 1) & 0x7);
        target[5] = (uint8_t)((state[1] << 2) & 0x4)
            | (uint8_t)((state[2] >> 6) & 0x3);
        target[6] = (uint8_t)((state[2] >> 3) & 0x7);
        target[7] = (uint8_t)(state[2] & 0x7);

        target[8] = (uint8_t)((state[3] >> 5) & 0x7);
        target[9] = (uint8_t)((state[3] >> 2) & 0x7);
        target[10] = (uint8_t)((state[3] << 1) & 0x6)
                    | (uint8_t)((state[4] >> 7) & 0x1);
        target[11] = (uint8_t)((state[4] >> 4) & 0x7);

        target[12] = (uint8_t)((state[4] >> 1) & 0x7);
        target[13] = (uint8_t)((state[4] << 2) & 0x4)
                    | (uint8_t)((state[5] >> 6) & 0x3);
        target[14] = (uint8_t)((state[5] >> 3) & 0x7);
        target[15] = (uint8_t)(state[5] & 0x7);
    }

    // ---------------------------------------------------------------------

    static void
    to_state(mini_aes_state_t target, const mini_aes_internal_state_t state) {
        // 000 111 222 333 ... fff
        // becomes
        // 00011122 23334445 55666777 888999aa abbbcccd ddeeefff

        target[0] = (state[0] << 5) | (state[1] << 2) | (state[2] >> 1);
        target[1] = (uint8_t)(((state[2] << 7) | (state[3] << 4) | (state[4] << 1) | (state[5] >> 2)) & 0xFF);
        target[2] = (uint8_t)(((state[5] << 6) | (state[6] << 3) | state[7]) & 0xFF);

        target[3] = (state[8] << 5) | (state[9] << 2) | (state[10] >> 1);
        target[4] = (uint8_t)(((state[10] << 7) | (state[11] << 4) | (state[12] << 1) | (state[13] >> 2)) & 0xFF);
        target[5] = (uint8_t)(((state[13] << 6) | (state[14] << 3) | state[15]) & 0xFF);
    }

    // ---------------------------------------------------------------------

    static
    void mini_aes_add_round_key(mini_aes_internal_state_t state,
                                const mini_aes_internal_state_t round_key) {
        utils::xor_arrays(state, state, round_key,
                          MINI_AES_NUM_INTERNAL_STATE_BYTES);
    }

    // ---------------------------------------------------------------------

    static void mini_aes_mix_column(mini_aes_internal_state_t result,
                                    const mini_aes_internal_state_t state,
                                    const size_t start_index) {
        result[start_index] = MINI_AES_TIMES_TWO[state[start_index]]
                              ^ MINI_AES_TIMES_THREE[state[start_index + 1]]
                              ^ state[start_index + 2]
                              ^ state[start_index + 3];
        result[start_index + 1] = state[start_index]
                                  ^ MINI_AES_TIMES_TWO[state[start_index + 1]]
                                  ^ MINI_AES_TIMES_THREE[state[start_index + 2]]
                                  ^ state[start_index + 3];
        result[start_index + 2] = state[start_index]
                                  ^ state[start_index + 1]
                                  ^ MINI_AES_TIMES_TWO[state[start_index + 2]]
                                  ^
                                  MINI_AES_TIMES_THREE[state[start_index + 3]];
        result[start_index + 3] = MINI_AES_TIMES_THREE[state[start_index]]
                                  ^ state[start_index + 1]
                                  ^ state[start_index + 2]
                                  ^ MINI_AES_TIMES_TWO[state[start_index + 3]];
    }

    // ---------------------------------------------------------------------

    static void mini_aes_mix_columns(mini_aes_internal_state_t state) {
        mini_aes_internal_state_t result;
        mini_aes_mix_column(result, state, 0);
        mini_aes_mix_column(result, state, 4);
        mini_aes_mix_column(result, state, 8);
        mini_aes_mix_column(result, state, 12);
        memcpy(state, result, MINI_AES_NUM_CELLS);
    }

    // ---------------------------------------------------------------------

    static void mini_aes_shift_rows(mini_aes_internal_state_t state) {
        mini_aes_internal_state_t result;

        for (size_t i = 0; i < MINI_AES_NUM_CELLS; ++i) {
            const size_t j = MINI_AES_SHIFT_ROWS_PERMUTATION[i];
            result[i] = state[j];
        }

        memcpy(state, result, MINI_AES_NUM_CELLS);
    }

    // ---------------------------------------------------------------------

    static void mini_aes_sub_cells(mini_aes_internal_state_t state) {
        for (size_t i = 0; i < MINI_AES_NUM_CELLS; ++i) {
            state[i] = MINI_AES_SBOX_ARRAY[state[i]];
        }
    }

    // ---------------------------------------------------------------------

    static void mini_aes_encrypt_round(const mini_aes_ctx_t *ctx,
                                         mini_aes_internal_state_t state,
                                         const size_t round_index) {
        mini_aes_sub_cells(state);
        mini_aes_shift_rows(state);
        mini_aes_mix_columns(state);
        mini_aes_add_round_key(state, ctx->key[round_index]);
    }

    // ---------------------------------------------------------------------

    static void mini_aes_encrypt_last_round(const mini_aes_ctx_t *ctx,
                                              mini_aes_internal_state_t state,
                                              const size_t round_index) {
        mini_aes_sub_cells(state);
        mini_aes_shift_rows(state);
        mini_aes_add_round_key(state, ctx->key[round_index]);
    }

    // ---------------------------------------------------------------------

    static void generate_round_key(mini_aes_internal_state_t next,
                                   mini_aes_internal_state_t previous,
                                   const size_t round_index) {
        uint8_t last_row[4];
        last_row[0] = MINI_AES_SBOX_ARRAY[previous[13]];
        last_row[1] = MINI_AES_SBOX_ARRAY[previous[14]];
        last_row[2] = MINI_AES_SBOX_ARRAY[previous[15]];
        last_row[3] = MINI_AES_SBOX_ARRAY[previous[12]];

        last_row[0] ^= MINI_AES_ROUND_CONSTANTS[round_index];

        next[0] = previous[0] ^ last_row[0];
        next[1] = previous[1] ^ last_row[1];
        next[2] = previous[2] ^ last_row[2];
        next[3] = previous[3] ^ last_row[3];

        for (size_t i = 1; i < MINI_AES_NUM_COLUMNS; ++i) {
            const size_t start_index = i * MINI_AES_NUM_ROWS;
            next[start_index] = previous[start_index] ^ next[start_index - 4];
            next[start_index + 1] = previous[start_index + 1] ^ next[start_index - 3];
            next[start_index + 2] = previous[start_index + 2] ^ next[start_index - 2];
            next[start_index + 3] = previous[start_index + 3] ^ next[start_index - 1];
        }
    }

    // ---------------------------------------------------------------------

    void mini_aes_key_setup(mini_aes_ctx_t *ctx, const mini_aes_key_t key) {
        to_internal_state(ctx->key[0], key);

        for (size_t i = 1; i < MINI_AES_NUM_ROUND_KEYS; ++i) {
            generate_round_key(ctx->key[i], ctx->key[i - 1], i);
        }
    }

    // ---------------------------------------------------------------------

    void mini_aes_encrypt(const mini_aes_ctx_t *ctx,
                          const mini_aes_state_t plaintext,
                          mini_aes_state_t ciphertext) {
        mini_aes_internal_state_t state;
        to_internal_state(state, plaintext);

        mini_aes_add_round_key(state, ctx->key[0]);

        for (size_t i = 1; i < MINI_AES_NUM_ROUNDS; ++i) {
            mini_aes_encrypt_round(ctx, state, i);
        }

        mini_aes_encrypt_last_round(ctx, state, MINI_AES_NUM_ROUNDS);
        to_state(ciphertext, state);
    }

    // ---------------------------------------------------------------------

    void mini_aes_encrypt_rounds(const mini_aes_ctx_t *ctx,
                                 const mini_aes_state_t plaintext,
                                 mini_aes_state_t ciphertext,
                                 const size_t num_rounds) {
        assert(num_rounds <= MINI_AES_NUM_ROUNDS);

        mini_aes_internal_state_t state;
        to_internal_state(state, plaintext);

        mini_aes_add_round_key(state, ctx->key[0]);

        for (size_t i = 1; i < num_rounds; ++i) {
            mini_aes_encrypt_round(ctx, state, i);
        }

        if (num_rounds >= MINI_AES_NUM_ROUNDS) {
            mini_aes_encrypt_last_round(ctx, state, num_rounds);
        } else {
            mini_aes_encrypt_round(ctx, state, num_rounds);
        }

        to_state(ciphertext, state);
    }

}
