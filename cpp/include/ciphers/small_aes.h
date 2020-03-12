/**
 * C implementation of Small-AES.
 * 
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#ifndef _SMALL_AES_H_
#define _SMALL_AES_H_

// ---------------------------------------------------------------------

#include <emmintrin.h>
#include <immintrin.h>
#include <wmmintrin.h>
#include <smmintrin.h>
#include <stdint.h>

#include "utils/utils.h"

namespace ciphers {

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

#define SMALL_AES_NUM_STATE_BYTES   8
#define SMALL_AES_NUM_KEY_BYTES     8

#define SMALL_AES_NUM_ROUNDS       10
#define SMALL_AES_NUM_ROUND_KEYS   11
#define SMALL_AES_NUM_ROWS          4
#define SMALL_AES_NUM_COLUMNS       4

#define aesdec(x, k)       _mm_aesdec_si128(x, k)
#define aesdeclast(x, k)   _mm_aesdeclast_si128(x, k)
#define aesenc(x, k)       _mm_aesenc_si128(x, k)
#define aesenclast(x, k)   _mm_aesenclast_si128(x, k)


#define SMALL_AES_TIMES_TWO             vsetr8(0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x3, 0x1, 0x7, 0x5, 0xb, 0x9, 0xf, 0xd)
#define SMALL_AES_TIMES_THREE           vsetr8(0x0, 0x3, 0x6, 0x5, 0xc, 0xf, 0xa, 0x9, 0xb, 0x8, 0xd, 0xe, 0x7, 0x4, 0x1, 0x2)

#define SMALL_AES_TIMES_9               vsetr8(0x0, 0x9, 0x1, 0x8, 0x2, 0xb, 0x3, 0xa, 0x4, 0xd, 0x5, 0xc, 0x6, 0xf, 0x7, 0xe)
#define SMALL_AES_TIMES_11              vsetr8(0x0, 0xb, 0x5, 0xe, 0xa, 0x1, 0xf, 0x4, 0x7, 0xc, 0x2, 0x9, 0xd, 0x6, 0x8, 0x3)
#define SMALL_AES_TIMES_13              vsetr8(0x0, 0xd, 0x9, 0x4, 0x1, 0xc, 0x8, 0x5, 0x2, 0xf, 0xb, 0x6, 0x3, 0xe, 0xa, 0x7)
#define SMALL_AES_TIMES_14              vsetr8(0x0, 0xe, 0xf, 0x1, 0xd, 0x3, 0x2, 0xc, 0x9, 0x7, 0x6, 0x8, 0x4, 0xa, 0xb, 0x5)

#define SMALL_AES_SBOX_1                vsetr8(0x06, 0x0b, 0x05, 0x04, 0x02, 0x0e, 0x07, 0x0a, 0x09, 0x0d, 0x0f, 0x0c, 0x03, 0x01, 0x00, 0x08)

    static const size_t SMALL_AES_SBOX_ARRAY[16] = {
        0x06, 0x0b, 0x05, 0x04, 0x02, 0x0e, 0x07, 0x0a,
        0x09, 0x0d, 0x0f, 0x0c, 0x03, 0x01, 0x00, 0x08
    };

    static const size_t SMALL_AES_INVERSE_SBOX_ARRAY[16] = {
        0x0e, 0x0d, 0x04, 0x0c, 0x03, 0x02, 0x00, 0x06,
        0x0f, 0x08, 0x07, 0x01, 0x0b, 0x09, 0x05, 0x0a
    };

    // ---------------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------------

    typedef uint8_t small_aes_key_t[SMALL_AES_NUM_KEY_BYTES];

    ALIGN(16)
    typedef uint8_t small_aes_state_t[SMALL_AES_NUM_STATE_BYTES];

    ALIGN(32)
    typedef struct {
        __m128i key[SMALL_AES_NUM_ROUND_KEYS];
        __m128i key_2[SMALL_AES_NUM_ROUND_KEYS];
        __m256i key_4[SMALL_AES_NUM_ROUND_KEYS];
    } small_aes_ctx_t;

    // ---------------------------------------------------------------------
    // API
    // ---------------------------------------------------------------------

    void to_byte_array(small_aes_state_t output, __m128i input);

    // ---------------------------------------------------------------------

    __m128i to_lower_nibbles(const small_aes_state_t input);

    // ---------------------------------------------------------------------

    __m128i to_nibbles(const uint8_t *input);

    // ---------------------------------------------------------------------

    void small_aes_decrypt(const small_aes_ctx_t *ctx,
                           const small_aes_state_t ciphertext,
                           small_aes_state_t plaintext);

    // ---------------------------------------------------------------------

    void small_aes_encrypt(const small_aes_ctx_t *ctx,
                           const small_aes_state_t plaintext,
                           small_aes_state_t ciphertext);

    // ---------------------------------------------------------------------

    void small_aes_encrypt_rounds(const small_aes_ctx_t *ctx,
                                  const small_aes_state_t plaintext,
                                  small_aes_state_t ciphertext,
                                  size_t num_rounds);

    // ---------------------------------------------------------------------

    void small_aes_encrypt_rounds_always_mc(const small_aes_ctx_t *ctx,
                                            const small_aes_state_t plaintext,
                                            small_aes_state_t ciphertext,
                                            size_t num_rounds);

    // ---------------------------------------------------------------------

    void small_aes_decrypt_rounds_always_mc(const small_aes_ctx_t *ctx,
                                            const small_aes_state_t ciphertext,
                                            small_aes_state_t plaintext,
                                            size_t num_rounds);

    // ---------------------------------------------------------------------

    void small_aes_encrypt_rounds_only_sbox_in_final(
        const small_aes_ctx_t *ctx,
        const small_aes_state_t plaintext,
        small_aes_state_t ciphertext,
        size_t num_rounds);

    // ---------------------------------------------------------------------

    __m128i
    small_aes_encrypt_rounds_only_sbox_in_final_with_aes_ni(
        const small_aes_ctx_t *ctx,
        __m128i plaintext,
        size_t num_rounds);

    // ---------------------------------------------------------------------

    void small_aes_key_setup(small_aes_ctx_t *ctx, const small_aes_key_t key);

    // ---------------------------------------------------------------------

    __m128i small_aes_encrypt_round(__m128i state, __m128i round_key);

    // ---------------------------------------------------------------------

    __m128i small_aes_decrypt_round(__m128i state, __m128i round_key);

    // ---------------------------------------------------------------------

    __m128i
    small_aes_encrypt_last_round(__m128i state, __m128i round_key);

    // ---------------------------------------------------------------------

    __m128i
    small_aes_decrypt_last_round(__m128i state, __m128i round_key);

    // ---------------------------------------------------------------------

    __m128i small_aes_shift_rows(__m128i state);

    // ---------------------------------------------------------------------

    __m128i small_aes_invert_shift_rows(__m128i state);

    // ---------------------------------------------------------------------

    __m128i small_aes_sub_bytes(__m128i state);

    // ---------------------------------------------------------------------

    __m128i small_aes_invert_sub_bytes(__m128i state);

    // ---------------------------------------------------------------------

    __m128i small_aes_mix_columns(__m128i state);

    // ---------------------------------------------------------------------

    __m128i small_aes_invert_mix_columns(__m128i state);

    // ---------------------------------------------------------------------

    void small_aes_encrypt_2(const small_aes_ctx_t *ctx,
                             const uint8_t *plaintexts,
                             uint8_t *ciphertexts);

    // ---------------------------------------------------------------------

    void small_aes_encrypt_rounds_2(const small_aes_ctx_t *ctx,
                                    const uint8_t *plaintexts,
                                    uint8_t *ciphertexts,
                                    size_t num_rounds);

    // ---------------------------------------------------------------------

    void small_aes_key_setup_2(small_aes_ctx_t *ctx);

    // ---------------------------------------------------------------------

    __m128i small_aes_encrypt_round_2(__m128i state, __m128i round_key);

    // ---------------------------------------------------------------------

    __m128i small_aes_encrypt_last_round_2(__m128i state, __m128i round_key);

    // ---------------------------------------------------------------------

    __m128i small_aes_shift_rows_2(__m128i state);

    // ---------------------------------------------------------------------

    __m128i small_aes_sub_bytes_2(__m128i state);

    // ---------------------------------------------------------------------

    __m128i small_aes_mix_columns_2(__m128i state);

    // ---------------------------------------------------------------------

    void small_aes_encrypt_4(const small_aes_ctx_t *ctx,
                             const uint8_t *plaintexts,
                             uint8_t *ciphertexts);

    // ---------------------------------------------------------------------

    void small_aes_encrypt_rounds_4(const small_aes_ctx_t *ctx,
                                    const uint8_t *plaintexts,
                                    uint8_t *ciphertexts,
                                    size_t num_rounds);

    // ---------------------------------------------------------------------

    void
    small_aes_encrypt_rounds_4_only_sbox_in_final(const small_aes_ctx_t *ctx,
                                                  const uint8_t *plaintexts,
                                                  uint8_t *ciphertexts,
                                                  size_t num_rounds);

    // ---------------------------------------------------------------------

    __m256i
    small_aes_encrypt_rounds_4_only_sbox_in_final_to_m256(
        const small_aes_ctx_t *ctx,
        const uint8_t *plaintexts,
        size_t num_rounds);

    // ---------------------------------------------------------------------

    void to_byte_array_4(uint8_t output[32], __m256i input);

    // ---------------------------------------------------------------------

    void small_aes_key_setup_4(small_aes_ctx_t *ctx);

    // ---------------------------------------------------------------------

    __m256i small_aes_encrypt_round_4(__m256i state, __m256i round_key);

    // ---------------------------------------------------------------------

    __m256i small_aes_encrypt_last_round_4(__m256i state, __m256i round_key);

    // ---------------------------------------------------------------------

    __m256i small_aes_shift_rows_4(__m256i state);

    // ---------------------------------------------------------------------

    __m256i small_aes_sub_bytes_4(__m256i state);

    // ---------------------------------------------------------------------

    __m256i small_aes_custom_sbox_sub_bytes_4(__m256i state, const __m128i sbox);

    // ---------------------------------------------------------------------

    __m256i small_aes_mix_columns_4(__m256i state);

    // ---------------------------------------------------------------------

}

#endif  // _SMALL_AES_H_
