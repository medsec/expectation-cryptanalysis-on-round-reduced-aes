/**
 * C implementation of Small-AES.
 * 
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#ifndef _SMALL_AES_RANDOM_SBOX_H_
#define _SMALL_AES_RANDOM_SBOX_H_

// ---------------------------------------------------------------------

#include <emmintrin.h>
#include <immintrin.h>
#include <wmmintrin.h>
#include <smmintrin.h>
#include <stdint.h>

#include "ciphers/small_aes.h"
#include "utils/utils.h"

namespace ciphers {

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

#define SMALL_AES_RANDOM_SBOX0   vsetr8(0x0f, 0x06, 0x07, 0x08, 0x0a, 0x0d, 0x00, 0x05, 0x0e, 0x0c, 0x0b, 0x03, 0x09, 0x04, 0x02, 0x01)
#define SMALL_AES_RANDOM_SBOX1   vsetr8(0x04, 0x09, 0x06, 0x0a, 0x0e, 0x07, 0x0b, 0x0c, 0x01, 0x05, 0x0d, 0x08, 0x00, 0x03, 0x02, 0x0f)
#define SMALL_AES_RANDOM_SBOX2   vsetr8(0x08, 0x04, 0x01, 0x0b, 0x00, 0x05, 0x0c, 0x0d, 0x02, 0x06, 0x0f, 0x09, 0x0e, 0x07, 0x03, 0x0a)
#define SMALL_AES_RANDOM_SBOX3   vsetr8(0x07, 0x01, 0x05, 0x0a, 0x04, 0x0b, 0x0c, 0x03, 0x0d, 0x08, 0x09, 0x0f, 0x0e, 0x02, 0x00, 0x06)
#define SMALL_AES_RANDOM_SBOX4   vsetr8(0x05, 0x01, 0x0e, 0x09, 0x06, 0x0b, 0x08, 0x0f, 0x0a, 0x0c, 0x0d, 0x02, 0x04, 0x00, 0x07, 0x03)
#define SMALL_AES_RANDOM_SBOX5   vsetr8(0x02, 0x0d, 0x0f, 0x05, 0x0b, 0x00, 0x09, 0x0a, 0x04, 0x01, 0x06, 0x0c, 0x08, 0x07, 0x0e, 0x03)
#define SMALL_AES_RANDOM_SBOX6   vsetr8(0x0c, 0x04, 0x00, 0x07, 0x09, 0x06, 0x0d, 0x03, 0x05, 0x0e, 0x08, 0x0a, 0x02, 0x0f, 0x01, 0x0b)
#define SMALL_AES_RANDOM_SBOX7   vsetr8(0x0f, 0x0e, 0x08, 0x0a, 0x07, 0x0d, 0x05, 0x02, 0x00, 0x0c, 0x01, 0x0b, 0x04, 0x09, 0x03, 0x06)
#define SMALL_AES_RANDOM_SBOX8   vsetr8(0x0f, 0x0e, 0x0d, 0x03, 0x05, 0x07, 0x04, 0x01, 0x02, 0x09, 0x00, 0x0c, 0x0a, 0x06, 0x08, 0x0b)
#define SMALL_AES_RANDOM_SBOX9   vsetr8(0x07, 0x06, 0x04, 0x08, 0x0e, 0x0f, 0x0c, 0x0b, 0x02, 0x00, 0x0d, 0x05, 0x09, 0x03, 0x01, 0x0a)
#define SMALL_AES_RANDOM_SBOX10   vsetr8(0x06, 0x02, 0x00, 0x09, 0x0d, 0x03, 0x0c, 0x0b, 0x05, 0x0e, 0x07, 0x0a, 0x04, 0x01, 0x0f, 0x08)
#define SMALL_AES_RANDOM_SBOX11   vsetr8(0x04, 0x0e, 0x09, 0x08, 0x06, 0x05, 0x02, 0x0d, 0x0f, 0x01, 0x00, 0x0a, 0x0b, 0x0c, 0x03, 0x07)
#define SMALL_AES_RANDOM_SBOX12   vsetr8(0x0c, 0x06, 0x02, 0x01, 0x09, 0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x0a, 0x00, 0x03, 0x04, 0x05, 0x0f)
#define SMALL_AES_RANDOM_SBOX13   vsetr8(0x01, 0x0a, 0x0f, 0x00, 0x0d, 0x0b, 0x0e, 0x04, 0x06, 0x08, 0x07, 0x0c, 0x02, 0x05, 0x03, 0x09)
#define SMALL_AES_RANDOM_SBOX14   vsetr8(0x09, 0x00, 0x0b, 0x06, 0x0f, 0x0e, 0x0a, 0x0c, 0x05, 0x01, 0x08, 0x0d, 0x02, 0x07, 0x04, 0x03)
#define SMALL_AES_RANDOM_SBOX15   vsetr8(0x01, 0x05, 0x04, 0x0e, 0x03, 0x0d, 0x0a, 0x08, 0x0f, 0x02, 0x06, 0x09, 0x0b, 0x00, 0x07, 0x0c)
#define SMALL_AES_RANDOM_SBOX16   vsetr8(0x0b, 0x07, 0x00, 0x0f, 0x09, 0x02, 0x0d, 0x08, 0x03, 0x05, 0x0c, 0x01, 0x0e, 0x0a, 0x06, 0x04)
#define SMALL_AES_RANDOM_SBOX17   vsetr8(0x0b, 0x0e, 0x0d, 0x08, 0x02, 0x07, 0x0c, 0x06, 0x05, 0x00, 0x04, 0x0f, 0x0a, 0x09, 0x03, 0x01)
#define SMALL_AES_RANDOM_SBOX18   vsetr8(0x09, 0x08, 0x00, 0x05, 0x0d, 0x0c, 0x0b, 0x06, 0x0e, 0x01, 0x03, 0x0f, 0x02, 0x0a, 0x04, 0x07)
#define SMALL_AES_RANDOM_SBOX19   vsetr8(0x03, 0x01, 0x0a, 0x0f, 0x0d, 0x05, 0x06, 0x04, 0x0b, 0x0c, 0x0e, 0x02, 0x00, 0x09, 0x08, 0x07)

    const __m128i SMALL_AES_RANDOM_SBOXES[20] = {
        SMALL_AES_RANDOM_SBOX0,
        SMALL_AES_RANDOM_SBOX1,
        SMALL_AES_RANDOM_SBOX2,
        SMALL_AES_RANDOM_SBOX3,
        SMALL_AES_RANDOM_SBOX4,
        SMALL_AES_RANDOM_SBOX5,
        SMALL_AES_RANDOM_SBOX6,
        SMALL_AES_RANDOM_SBOX7,
        SMALL_AES_RANDOM_SBOX8,
        SMALL_AES_RANDOM_SBOX9,
        SMALL_AES_RANDOM_SBOX10,
        SMALL_AES_RANDOM_SBOX11,
        SMALL_AES_RANDOM_SBOX12,
        SMALL_AES_RANDOM_SBOX13,
        SMALL_AES_RANDOM_SBOX14,
        SMALL_AES_RANDOM_SBOX15,
        SMALL_AES_RANDOM_SBOX16,
        SMALL_AES_RANDOM_SBOX17,
        SMALL_AES_RANDOM_SBOX18,
        SMALL_AES_RANDOM_SBOX19
    };

    // ---------------------------------------------------------------------

    void
    small_aes_random_sbox_encrypt_rounds_always_mc(const small_aes_ctx_t *ctx,
                                                   const small_aes_state_t plaintext,
                                                   small_aes_state_t ciphertext,
                                                   size_t num_rounds,
                                                   size_t sbox_index);

    // ---------------------------------------------------------------------

    void small_aes_random_sbox_encrypt_rounds_only_sbox_in_final(
        const small_aes_ctx_t *ctx,
        const small_aes_state_t plaintext,
        small_aes_state_t ciphertext,
        size_t num_rounds,
        size_t sbox_index);

    // ---------------------------------------------------------------------

    __m128i
    small_aes_random_sbox_encrypt_rounds_only_sbox_in_final_with_aes_ni(
        const small_aes_ctx_t *ctx,
        __m128i plaintext,
        size_t num_rounds,
        size_t sbox_index);

    // ---------------------------------------------------------------------

}

#endif  // _SMALL_AES_RANDOM_SBOX_H_
