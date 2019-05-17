/**
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */ 

// ---------------------------------------------------------------------

#include <emmintrin.h>
#include <wmmintrin.h>
#include <smmintrin.h>
#include <stdint.h>

#include "ciphers/aes.h"
#include "utils/utils.h"

// ---------------------------------------------------------------------

namespace ciphers {

    static const __m128i AES_SHIFT_ROWS_MASK = vset32(0x0B06010C, 0x07020D08,
                                                      0x030E0904, 0x0F0A0500);
    static const __m128i AES_INVERSE_SHIFT_ROWS_MASK = vset32(0x0306090c,
                                                              0x0f020508,
                                                              0x0b0e0104,
                                                              0x070a0d00);

    // ---------------------------------------------------------------------

    void aes128_decrypt(const aes128_ctx_t *ctx,
                        const aes_state_t ciphertext,
                        aes_state_t plaintext) {
        __m128i state = loadu(ciphertext);
        const __m128i *keys = ctx->decryption_keys;

        state = vxor(state, keys[0]);

        for (size_t i = 1; i < AES_128_NUM_ROUNDS; ++i) {
            state = aesdec(state, keys[i]);
        }

        state = aesdeclast(state, keys[AES_128_NUM_ROUNDS]);
        storeu(plaintext, state);
    }

    // ---------------------------------------------------------------------

    void aes128_encrypt(const aes128_ctx_t *ctx,
                        const aes_state_t plaintext,
                        aes_state_t ciphertext) {
        aes128_encrypt_rounds(ctx, plaintext, ciphertext, AES_128_NUM_ROUNDS);
    }

    // ---------------------------------------------------------------------

    void aes128_encrypt_rounds(const aes128_ctx_t *ctx,
                               const aes_state_t plaintext,
                               aes_state_t ciphertext,
                               const size_t num_rounds) {
        if (num_rounds > AES_128_NUM_ROUNDS) {
            return;
        }

        __m128i state = loadu(plaintext);
        const __m128i *keys = ctx->encryption_keys;

        state = vxor(state, keys[0]);

        for (size_t i = 1; i < num_rounds; ++i) {
            state = aesenc(state, keys[i]);
        }

        state = aesenclast(state, keys[num_rounds]);
        storeu(ciphertext, state);
    }

    // ---------------------------------------------------------------------

    void aes128_encrypt_rounds_always_mc(const aes128_ctx_t *ctx,
                                         const aes_state_t plaintext,
                                         aes_state_t ciphertext,
                                         size_t num_rounds)  {
        if (num_rounds > AES_128_NUM_ROUNDS) {
            return;
        }

        if (num_rounds == 0) {
            memcpy(ciphertext, plaintext, AES_NUM_STATE_BYTES);
            return;
        }

        __m128i state = loadu(plaintext);
        const __m128i *keys = ctx->encryption_keys;

        state = vxor(state, keys[0]);

        for (size_t i = 1; i <= num_rounds; ++i) {
            state = aesenc(state, keys[i]);
        }

        storeu(ciphertext, state);
    }

    // ---------------------------------------------------------------------

    void aes128_encrypt_rounds_always_mc_4(const aes128_ctx_t *ctx,
                                           const aes_state_t plaintexts[4],
                                           aes_state_t ciphertexts[4],
                                           size_t num_rounds)  {
        if (num_rounds > AES_128_NUM_ROUNDS) {
            return;
        }

        if (num_rounds == 0) {
            memcpy(ciphertexts, plaintexts, 4 * AES_NUM_STATE_BYTES);
            return;
        }

        __m128i states[4];

        for (size_t j = 0; j < 4; ++j) {
            states[j] = loadu(plaintexts[j]);
        }

        const __m128i *keys = ctx->encryption_keys;

        vxor4(states, keys);

        for (size_t i = 1; i <= num_rounds; ++i) {
            aesenc4(states, keys[i]);
        }

        for (size_t j = 0; j < 4; ++j) {
            storeu(ciphertexts[j], states[j]);
        }
    }

    // ---------------------------------------------------------------------

    void aes128_encrypt_rounds_only_sbox_in_final(const aes128_ctx_t *ctx,
                                                  const aes_state_t plaintext,
                                                  aes_state_t ciphertext,
                                                  const size_t num_rounds) {
        if (num_rounds > AES_128_NUM_ROUNDS) {
            return;
        }

        __m128i state = loadu(plaintext);
        const __m128i *keys = ctx->encryption_keys;

        state = vxor(state, keys[0]);

        for (size_t i = 1; i < num_rounds; ++i) {
            state = aesenc(state, keys[i]);
        }

        state = aes_sub_bytes(state);
//        state = vxor(state, keys[num_rounds]);
        storeu(ciphertext, state);
    }

    // ---------------------------------------------------------------------

    inline
    static __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
        __m128i temp3;

        temp2 = _mm_shuffle_epi32(temp2, 0xff);
        temp3 = _mm_slli_si128(temp1, 0x4);

        temp1 = vxor(temp1, temp3);
        temp3 = _mm_slli_si128(temp3, 0x4);

        temp1 = vxor(temp1, temp3);
        temp3 = _mm_slli_si128(temp3, 0x4);

        temp1 = vxor(temp1, temp3);
        temp1 = vxor(temp1, temp2);

        return temp1;
    }

    // ---------------------------------------------------------------------

    void aes128_key_setup(aes128_ctx_t *ctx, const aes128_key_t key) {
        __m128i temp1, temp2;
        __m128i *encryption_keys = ctx->encryption_keys;
        __m128i *decryption_keys = ctx->decryption_keys;

        // ---------------------------------------------------------------------
        // Expand encryption key
        // ---------------------------------------------------------------------

        temp1 = loadu(key);
        encryption_keys[0] = temp1;

        // utils::print_128("Full AES K[0]", encryption_keys[0]);

        temp2 = _mm_aeskeygenassist_si128(temp1, 0x01);
        temp1 = AES_128_ASSIST(temp1, temp2);
        encryption_keys[1] = temp1;

        temp2 = _mm_aeskeygenassist_si128(temp1, 0x02);
        temp1 = AES_128_ASSIST(temp1, temp2);
        encryption_keys[2] = temp1;

        temp2 = _mm_aeskeygenassist_si128(temp1, 0x04);
        temp1 = AES_128_ASSIST(temp1, temp2);
        encryption_keys[3] = temp1;

        temp2 = _mm_aeskeygenassist_si128(temp1, 0x08);
        temp1 = AES_128_ASSIST(temp1, temp2);
        encryption_keys[4] = temp1;

        temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
        temp1 = AES_128_ASSIST(temp1, temp2);
        encryption_keys[5] = temp1;

        temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
        temp1 = AES_128_ASSIST(temp1, temp2);
        encryption_keys[6] = temp1;

        temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
        temp1 = AES_128_ASSIST(temp1, temp2);
        encryption_keys[7] = temp1;

        temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
        temp1 = AES_128_ASSIST(temp1, temp2);
        encryption_keys[8] = temp1;

        temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
        temp1 = AES_128_ASSIST(temp1, temp2);
        encryption_keys[9] = temp1;

        temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
        temp1 = AES_128_ASSIST(temp1, temp2);
        encryption_keys[10] = temp1;

        // ---------------------------------------------------------------------
        // Expand decryption key
        // ---------------------------------------------------------------------

        decryption_keys[0] = encryption_keys[AES_128_NUM_ROUNDS];

        for (size_t i = 1; i < AES_128_NUM_ROUNDS; ++i) {
            decryption_keys[i] = _mm_aesimc_si128(
                encryption_keys[AES_128_NUM_ROUNDS - i]);
        }

        decryption_keys[AES_128_NUM_ROUNDS] = encryption_keys[0];
    }

    // ---------------------------------------------------------------------

    __m128i aes_shift_rows(__m128i state) {
        return vshuffle(state, AES_SHIFT_ROWS_MASK);
    }

    // ---------------------------------------------------------------------

    __m128i aes_sub_bytes(__m128i state) {
        state = vshuffle(state, AES_INVERSE_SHIFT_ROWS_MASK);
        return aesenclast(state, zero);
    }

    // ---------------------------------------------------------------------

    __m128i aes_mix_columns(__m128i state) {
        state = aesdeclast(state, zero);
        return aesenc(state, zero);
    }

    // ---------------------------------------------------------------------

    __m128i aes_invert_shift_rows(__m128i state) {
        return vshuffle(state, AES_INVERSE_SHIFT_ROWS_MASK);
    }

    // ---------------------------------------------------------------------

    __m128i aes_invert_sub_bytes(__m128i state) {
        state = vshuffle(state, AES_SHIFT_ROWS_MASK);
        return aesdeclast(state, zero);
    }

    // ---------------------------------------------------------------------

    __m128i aes_invert_mix_columns(__m128i state) {
        state = aesenclast(state, zero);
        return aesdec(state, zero);
    }

}
