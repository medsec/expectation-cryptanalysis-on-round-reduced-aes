/**
 * C implementation of Small-AES.
 * 
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#ifndef _SMALL_AES_MIDORI_MC_H_
#define _SMALL_AES_MIDORI_MC_H_

// ---------------------------------------------------------------------

#include <emmintrin.h>
#include <immintrin.h>
#include <wmmintrin.h>
#include <smmintrin.h>
#include <stdint.h>

#include "ciphers/small_aes.h"
#include "utils/utils.h"

namespace ciphers {

    void
    small_aes_midori_mc_encrypt_rounds_always_mc(
        const small_aes_ctx_t *ctx,
        const small_aes_state_t plaintext,
        small_aes_state_t ciphertext,
        size_t num_rounds);

    // ---------------------------------------------------------------------

    void small_aes_midori_mc_encrypt_rounds_only_sbox_in_final(
        const small_aes_ctx_t *ctx,
        const small_aes_state_t plaintext,
        small_aes_state_t ciphertext,
        size_t num_rounds);

    // ---------------------------------------------------------------------

    __m128i
    small_aes_midori_mc_encrypt_rounds_only_sbox_in_final_with_aes_ni(
        const small_aes_ctx_t *ctx,
        __m128i plaintext,
        size_t num_rounds);

    // ---------------------------------------------------------------------

}

#endif  // _SMALL_AES_MIDORI_MC_H_
