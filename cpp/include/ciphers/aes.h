/**
 * C implementation of the AES.
 * 
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */ 

#ifndef _AES_H_
#define _AES_H_

// ---------------------------------------------------------------------

#include <emmintrin.h>
#include <wmmintrin.h>
#include <smmintrin.h>
#include <stdint.h>

#include "utils/utils.h"

namespace ciphers {

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

#define AES_NUM_STATE_BYTES    16

#define AES_128_NUM_ROUNDS     10
#define AES_128_NUM_ROUND_KEYS 11
#define AES_128_NUM_KEY_BYTES  16
#define AES_128_NUM_COLUMNS     4
#define AES_128_NUM_ROWS        4

    // ---------------------------------------------------------------------
    // Macros
    // ---------------------------------------------------------------------

#define aesdec(x, k)       _mm_aesdec_si128(x, k)
#define aesdeclast(x, k)   _mm_aesdeclast_si128(x, k)
#define aesenc(x, k)       _mm_aesenc_si128(x, k)
#define aesenclast(x, k)   _mm_aesenclast_si128(x, k)

#define aesenc4(x, y) {\
    x[0] = aesenc(x[0], y);\
    x[1] = aesenc(x[1], y);\
    x[2] = aesenc(x[2], y);\
    x[3] = aesenc(x[3], y);\
}

#define aesenclast4(x, y) {\
    x[0] = aesenclast(x[0], y);\
    x[1] = aesenclast(x[1], y);\
    x[2] = aesenclast(x[2], y);\
    x[3] = aesenclast(x[3], y);\
}

    // ---------------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------------

    typedef uint8_t aes128_key_t[AES_NUM_STATE_BYTES];

    typedef uint8_t aes_state_t[AES_NUM_STATE_BYTES];

    ALIGN(16)
    typedef struct {
        __m128i encryption_keys[AES_128_NUM_ROUND_KEYS];
        __m128i decryption_keys[AES_128_NUM_ROUND_KEYS];
    } aes128_ctx_t;

    // ---------------------------------------------------------------------
    // API
    // ---------------------------------------------------------------------

    void aes128_decrypt(const aes128_ctx_t *ctx,
                        const aes_state_t ciphertext,
                        aes_state_t plaintext);

    // ---------------------------------------------------------------------

    void aes128_encrypt(const aes128_ctx_t *ctx,
                        const aes_state_t plaintext,
                        aes_state_t ciphertext);

    // ---------------------------------------------------------------------

    void aes128_encrypt_rounds(const aes128_ctx_t *ctx,
                               const aes_state_t plaintext,
                               aes_state_t ciphertext,
                               const size_t num_rounds);

    // ---------------------------------------------------------------------

    void aes128_encrypt_rounds_always_mc(const aes128_ctx_t *ctx,
                                         const aes_state_t plaintext,
                                         aes_state_t ciphertext,
                                         size_t num_rounds);

    // ---------------------------------------------------------------------

    void aes128_encrypt_rounds_always_mc_4(const aes128_ctx_t *ctx,
                                           const aes_state_t plaintext[4],
                                           aes_state_t ciphertext[4],
                                           size_t num_rounds);

    // ---------------------------------------------------------------------

    void aes128_encrypt_rounds_only_sbox_in_final(const aes128_ctx_t *ctx,
                                                  const aes_state_t plaintext,
                                                  aes_state_t ciphertext,
                                                  const size_t num_rounds);

    // ---------------------------------------------------------------------

    void aes128_key_setup(aes128_ctx_t *ctx, const aes128_key_t key);

    // ---------------------------------------------------------------------

    __m128i aes_shift_rows(__m128i state);

    // ---------------------------------------------------------------------

    __m128i aes_sub_bytes(__m128i state);

    // ---------------------------------------------------------------------

    __m128i aes_mix_columns(__m128i state);

    // ---------------------------------------------------------------------

    __m128i aes_invert_shift_rows(__m128i state);

    // ---------------------------------------------------------------------

    __m128i aes_invert_sub_bytes(__m128i state);

    // ---------------------------------------------------------------------

    __m128i aes_invert_mix_columns(__m128i state);

    // ---------------------------------------------------------------------

}

#endif  // _AES_H_
