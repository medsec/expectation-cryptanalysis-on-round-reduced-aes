/**
 * C implementation of the AES.
 *
 * __author__ = anonymous
 * __date__   = 2018-05
 * __copyright__ = Creative Commons CC0
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ciphers/speck64.h"
#include "utils/utils.h"

namespace ciphers {

    // ---------------------------------------------------------
    // Basic functions and their inverses
    // ---------------------------------------------------------

    void speck64_round(uint32_t* left,
                       uint32_t* right,
                       const uint32_t* round_key) {
        (*left) = ROTR32((*left), 8);
        (*left) += (*right);
        (*left) ^= (*round_key);
        (*right) = ROTL32((*right), 3);
        (*right) ^= (*left);
    }

    // ---------------------------------------------------------

    void speck64_inverse_round(uint32_t* left,
                               uint32_t* right,
                               const uint32_t* round_key) {
        (*right) ^= (*left);
        (*right) = ROTR32((*right), 3);
        (*left) ^= (*round_key);
        (*left) -= (*right);
        (*left) = ROTL32((*left), 8);
    }

    // ---------------------------------------------------------
    // Key Schedule
    // ---------------------------------------------------------

    void speck64_96_key_schedule(speck64_context_t *ctx,
                                 const uint8_t *master_key) {
        uint32_t key[SPECK_64_96_NUM_KEY_BYTES];
        utils::to_uint32(key, master_key, SPECK_64_96_NUM_KEY_BYTES);
        uint32_t lp0 = 0;
        uint32_t lp1 = 0;
        uint32_t lp2 = 0;

        ctx->subkeys[0] = key[2];

        for (uint32_t i = 0; i < SPECK_64_96_NUM_ROUNDS - 1; ++i) {
            if (i == 0) {
                lp0 = key[1]; // L[1] = left
                lp1 = key[0]; // L[0] = right
            } else {
                lp0 = lp1;    // L[0] = new left
                lp1 = lp2;    // L[2] = next in pipeline
            }

            lp2 = (ROTR32(lp0, 8) + ctx->subkeys[i]) ^ i;           // left side
            ctx->subkeys[i + 1] = ROTL32(ctx->subkeys[i], 3) ^ lp2; // new right
        }
    }

    // ---------------------------------------------------------
    // API
    // ---------------------------------------------------------

    void speck64_encrypt_rounds(const speck64_context_t *ctx,
                                const uint8_t *plaintext,
                                uint8_t *ciphertext,
                                size_t num_rounds) {
        uint32_t state[2];
        utils::to_uint32(state, plaintext, SPECK_64_NUM_STATE_BYTES);

#ifdef DEBUG
        printf("Round %2d\n", 0);
        utils::print_hex("State (bytes)", (uint8_t*)state, 8);
        printf("Left  (uint)   %08x\n", state[0]);
        printf("Right (uint)   %08x\n", state[1]);
#endif

        for (size_t i = 0; i < num_rounds; ++i) {
            speck64_round(&(state[0]), &(state[1]), &(ctx->subkeys[i]));

#ifdef DEBUG
            printf("Round %2zu\n", i+1);
            utils::print_hex("State (bytes)", (uint8_t*)state, 8);
            printf("Left  (uint)   %08x\n", state[0]);
            printf("Right (uint)   %08x\n", state[1]);
            printf("Key   (uint)   %08x\n", ctx->subkeys[i]);
#endif
        }

        utils::to_uint8(ciphertext, state, SPECK_64_NUM_STATE_BYTES);
    }

    // ---------------------------------------------------------

    void speck64_decrypt_rounds(const speck64_context_t *ctx,
                                const uint8_t *ciphertext,
                                uint8_t *plaintext,
                                size_t num_rounds) {
        uint32_t state[2];
        utils::to_uint32(state, ciphertext, SPECK_64_NUM_STATE_BYTES);

#ifdef DEBUG
        printf("Round %2d\n", SPECK_64_96_NUM_ROUNDS);
        utils::print_hex("State (bytes)", (uint8_t*)state, 8);
        printf("Left  (uint)   %08x\n", state[0]);
        printf("Right (uint)   %08x\n", state[1]);
#endif

        for (int i = (int)num_rounds - 1; i >= 0; --i) {
            speck64_inverse_round(&(state[0]), &(state[1]), &(ctx->subkeys[i]));

#ifdef DEBUG
            printf("Round %2d\n", i);
            utils::print_hex("State (bytes)", (uint8_t*)state, 8);
            printf("Left  (uint)   %08x\n", state[0]);
            printf("Right (uint)   %08x\n", state[1]);
            printf("Key   (uint)   %08x\n", ctx->subkeys[i]);
#endif
        }

        utils::to_uint8(plaintext, state, SPECK_64_NUM_STATE_BYTES);
    }

    // ---------------------------------------------------------

    void speck64_encrypt(const speck64_context_t* ctx,
                         const uint8_t plaintext[SPECK_64_NUM_STATE_BYTES],
                         uint8_t ciphertext[SPECK_64_NUM_STATE_BYTES]) {
        speck64_encrypt_rounds(ctx, plaintext, ciphertext, SPECK_64_96_NUM_ROUNDS);
    }

    // ---------------------------------------------------------

    void speck64_decrypt(const speck64_context_t* ctx,
                         const uint8_t ciphertext[SPECK_64_NUM_STATE_BYTES],
                         uint8_t plaintext[SPECK_64_NUM_STATE_BYTES]) {
        speck64_decrypt_rounds(ctx, ciphertext, plaintext, SPECK_64_96_NUM_ROUNDS);
    }

}
