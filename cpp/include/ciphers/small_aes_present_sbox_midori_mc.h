/**
 * C implementation of Small-AES.
 * 
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#ifndef _SMALL_AES_PRESENT_SBOX_MIDORI_MC_H_
#define _SMALL_AES_PRESENT_SBOX_MIDORI_MC_H_

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

#define SMALL_AES_PRESENT_SBOX                  vsetr8(0x0c, 0x05, 0x06, 0x0b, 0x09, 0x00, 0x0a, 0x0d, 0x03, 0x0e, 0x0f, 0x08, 0x04, 0x07, 0x01, 0x02)
#define SMALL_AES_PRESENT_INVERSE_SBOX          vsetr8(0x05, 0x0e, 0x0f, 0x08, 0x0c, 0x01, 0x02, 0x0d, 0x0b, 0x04, 0x06, 0x03, 0x00, 0x07, 0x09, 0x0a)

    // ---------------------------------------------------------------------

    void
    small_aes_present_sbox_midori_mc_encrypt_rounds_always_mc(
        const small_aes_ctx_t *ctx,
        const small_aes_state_t plaintext,
        small_aes_state_t ciphertext,
        size_t num_rounds);

    // ---------------------------------------------------------------------

    void small_aes_present_sbox_midori_mc_encrypt_rounds_only_sbox_in_final(
        const small_aes_ctx_t *ctx,
        const small_aes_state_t plaintext,
        small_aes_state_t ciphertext,
        size_t num_rounds);

    // ---------------------------------------------------------------------

    __m128i
    small_aes_present_sbox_midori_mc_encrypt_rounds_only_sbox_in_final_with_aes_ni(
        const small_aes_ctx_t *ctx,
        __m128i plaintext,
        size_t num_rounds);

    // ---------------------------------------------------------------------

}

#endif  // _SMALL_AES_PRESENT_SBOX_MIDORI_MC_H_
