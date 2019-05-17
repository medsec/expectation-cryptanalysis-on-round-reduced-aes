/**
 * C implementation of a Mini version of the AES reduced to three-bit cells.
 *
 * __author__ = anonymized
 * __date__   = 2018-05
 * __copyright__ = Creative Commons CC0
 */

#ifndef _MINI_AES_H_
#define _MINI_AES_H_

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

#define MINI_AES_NUM_STATE_BYTES   6
#define MINI_AES_NUM_KEY_BYTES     6
#define MINI_AES_NUM_INTERNAL_STATE_BYTES     16

#define MINI_AES_NUM_ROUNDS       10
#define MINI_AES_NUM_ROUND_KEYS   11
#define MINI_AES_NUM_ROWS          4
#define MINI_AES_NUM_COLUMNS       4
#define MINI_AES_NUM_CELLS        16

    static const uint8_t MINI_AES_SBOX_ARRAY[8] = {
        0x0, 0x1, 0x3, 0x6, 0x7, 0x4, 0x5, 0x2
    };

    static const uint8_t MINI_AES_INVERSE_SBOX_ARRAY[8] = {
        0x0, 0x1, 0x7, 0x2, 0x5, 0x6, 0x3, 0x4
    };
    static const uint8_t MINI_AES_TIMES_TWO[8] = {
        0x0, 0x2, 0x4, 0x6, 0x3, 0x1, 0x7, 0x5
    };
    static const uint8_t MINI_AES_TIMES_THREE[8] = {
        0x0, 0x3, 0x6, 0x5, 0x7, 0x4, 0x1, 0x2
    };
    static const uint8_t MINI_AES_SHIFT_ROWS_PERMUTATION[16] = {
        0x0, 0x5, 0xa, 0xf, 0x4, 0x9, 0xe, 0x3, 0x8, 0xd, 0x2, 0x7, 0xc, 0x1, 0x6, 0xb
    };
    static const uint8_t MINI_AES_ROUND_CONSTANTS[MINI_AES_NUM_ROUND_KEYS] = {
        0x0, 0x1, 0x2, 0x4, 0x3, 0x6, 0x7, 0x5, 0x1, 0x2, 0x4
    };

    // ---------------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------------

    typedef uint8_t mini_aes_key_t[MINI_AES_NUM_KEY_BYTES];

    typedef uint8_t mini_aes_state_t[MINI_AES_NUM_STATE_BYTES];
    typedef uint8_t mini_aes_internal_state_t[MINI_AES_NUM_INTERNAL_STATE_BYTES];

    typedef struct {
        mini_aes_internal_state_t key[MINI_AES_NUM_ROUND_KEYS];
    } mini_aes_ctx_t;

    // ---------------------------------------------------------------------

    void mini_aes_key_setup(mini_aes_ctx_t *ctx, const mini_aes_key_t key);

    // ---------------------------------------------------------------------

    void mini_aes_encrypt(const mini_aes_ctx_t *ctx,
                          const mini_aes_state_t plaintext,
                          mini_aes_state_t ciphertext);

    // ---------------------------------------------------------------------

    void mini_aes_encrypt_rounds(const mini_aes_ctx_t *ctx,
                                 const mini_aes_state_t plaintext,
                                 mini_aes_state_t ciphertext,
                                 size_t num_rounds);

}

// ---------------------------------------------------------------------

#endif  // _MINI_AES_H_
