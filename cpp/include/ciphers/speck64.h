/**
 * C implementation of Speck-64.
 *
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#ifndef  _SPECK_H_
#define  _SPECK_H_

// ---------------------------------------------------------------------

#include <stdint.h>
#include <stdlib.h>

namespace ciphers {

// ---------------------------------------------------------
// Constants
// ---------------------------------------------------------

#define SPECK_64_96_NUM_KEY_BYTES   12
#define SPECK_64_128_NUM_KEY_BYTES  16
#define SPECK_64_NUM_STATE_BYTES     8
#define SPECK_64_96_NUM_ROUNDS      26
#define SPECK_64_128_NUM_ROUNDS     27

    // ---------------------------------------------------------
    // Types
    // ---------------------------------------------------------

    typedef struct {
        uint32_t subkeys[SPECK_64_96_NUM_ROUNDS];
    } speck64_context_t;

    typedef uint8_t speck64_96_key_t[SPECK_64_96_NUM_KEY_BYTES];
    typedef uint8_t speck64_128_key_t[SPECK_64_128_NUM_KEY_BYTES];
    typedef uint8_t speck64_state_t[SPECK_64_NUM_STATE_BYTES];

    // ---------------------------------------------------------
    // API
    // ---------------------------------------------------------

    void speck64_round(uint32_t *left,
                       uint32_t *right,
                       const uint32_t *round_key);

    // ---------------------------------------------------------

    void speck64_inverse_round(uint32_t *left, uint32_t *right,
                               const uint32_t *round_key);

    // ---------------------------------------------------------

    void speck64_96_key_schedule(speck64_context_t *ctx,
                                 const uint8_t *key);

    // ---------------------------------------------------------

    void speck64_encrypt_rounds(const speck64_context_t *ctx,
                                const uint8_t *plaintext,
                                uint8_t *ciphertext,
                                size_t num_rounds);

    // ---------------------------------------------------------

    void speck64_decrypt_rounds(const speck64_context_t *ctx,
                                const uint8_t *ciphertext,
                                uint8_t *plaintext,
                                size_t num_rounds);

    // ---------------------------------------------------------

    void speck64_encrypt(const speck64_context_t *ctx,
                         const uint8_t plaintext[SPECK_64_NUM_STATE_BYTES],
                         uint8_t ciphertext[SPECK_64_NUM_STATE_BYTES]);

    // ---------------------------------------------------------

    void speck64_decrypt(const speck64_context_t *ctx,
                         const uint8_t ciphertext[SPECK_64_NUM_STATE_BYTES],
                         uint8_t plaintext[SPECK_64_NUM_STATE_BYTES]);

}

// ---------------------------------------------------------------------

#endif // _SPECK_H_
