/**
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */
#include <stdint.h>
#include <stdlib.h>
#include <algorithm>
#include <vector>

#include "ciphers/random_function.h"
#include "ciphers/small_aes.h"
#include "utils/argparse.h"
#include "utils/utils.h"
#include "utils/xorshift1024.h"
#include "ciphers/small_state.h"


using ciphers::small_aes_ctx_t;
using ciphers::small_aes_state_t;
using ciphers::small_aes_key_t;
using ciphers::SmallState;
using utils::xor_arrays;
using utils::ArgumentParser;
using utils::xorshift_prng_ctx_t;

// ---------------------------------------------------------

typedef struct {
    small_aes_ctx_t cipher_ctx;
} ExperimentContext;

// ---------------------------------------------------------

static void perform_experiment(const ExperimentContext &context) {
    small_aes_ctx_t cipher_ctx = context.cipher_ctx;
    small_aes_key_t correct_key;

    utils::get_random_bytes(correct_key, SMALL_AES_NUM_KEY_BYTES);
    small_aes_key_setup(&cipher_ctx, correct_key);

    std::array<SmallState, 16> ciphertexts;

    const size_t NUM_ROUNDS = 1;

    small_aes_state_t base_plaintext;
    utils::get_random_bytes(base_plaintext, SMALL_AES_NUM_STATE_BYTES);

    for (size_t i = 0; i < 16; ++i) {
        small_aes_state_t plaintext;
        memcpy(plaintext, base_plaintext, SMALL_AES_NUM_STATE_BYTES);
        plaintext[0] = (uint8_t) ((base_plaintext[0] & 0x0F) |
                                  ((i << 4) & 0xF0));

        SmallState ciphertext;
        small_aes_encrypt_rounds_always_mc(&cipher_ctx, plaintext,
                                           ciphertext.state,
                                           NUM_ROUNDS);
        ciphertexts[i] = ciphertext;
    }

    for (size_t i = 0; i < 15; ++i) {
        SmallState ciphertext_i = ciphertexts[i];

        for (size_t j = i + 1; j < 16; ++j) {
            SmallState ciphertext_j = ciphertexts[j];

            small_aes_state_t difference_ij;
            utils::xor_arrays(difference_ij, ciphertext_i.state,
                              ciphertext_j.state, SMALL_AES_NUM_STATE_BYTES);
            printf("%2zu %2zu", i, j);
            utils::print_hex("", difference_ij, SMALL_AES_NUM_STATE_BYTES);
        }
    }

    small_aes_state_t plaintext00;
    small_aes_state_t plaintext01;

    utils::get_random_bytes(plaintext00, SMALL_AES_NUM_STATE_BYTES);
    memcpy(plaintext01, plaintext00, SMALL_AES_NUM_STATE_BYTES);
    plaintext01[0] = plaintext00[0] ^ 0x10;

    utils::print_hex("P_00", plaintext00, SMALL_AES_NUM_STATE_BYTES);
    utils::print_hex("P_01", plaintext01, SMALL_AES_NUM_STATE_BYTES);

    small_aes_state_t ciphertext00;
    small_aes_state_t ciphertext01;

    small_aes_encrypt_rounds_always_mc(&cipher_ctx, plaintext00,
                                       ciphertext00,
                                       NUM_ROUNDS);

    small_aes_encrypt_rounds_always_mc(&cipher_ctx, plaintext01,
                                       ciphertext01,
                                       NUM_ROUNDS);

   utils::print_hex("C_00", ciphertext00, SMALL_AES_NUM_STATE_BYTES);
   utils::print_hex("C_01", ciphertext01, SMALL_AES_NUM_STATE_BYTES);

   // Build a mixture: C10, C11
   // 3000    2000
   // 2000    3000
   // 2000    3000
   // 2000    3000

   small_aes_state_t ciphertext10;
   small_aes_state_t ciphertext11;

   memcpy(ciphertext10, ciphertext00, SMALL_AES_NUM_STATE_BYTES);
   memcpy(ciphertext11, ciphertext01, SMALL_AES_NUM_STATE_BYTES);

   ciphertext10[0] = (uint8_t) ((ciphertext01[0] & 0xF0) |
                                (ciphertext00[0] & 0x0F));
   ciphertext11[0] = (uint8_t) ((ciphertext00[0] & 0xF0) |
                                (ciphertext01[0] & 0x0F));

   utils::print_hex("C_10", ciphertext10, SMALL_AES_NUM_STATE_BYTES);
   utils::print_hex("C_11", ciphertext11, SMALL_AES_NUM_STATE_BYTES);

   // Decrypt them to P10, P11. Are they in a delta set?

   small_aes_state_t plaintext10;
   small_aes_state_t plaintext11;

   small_aes_decrypt_rounds_always_mc(&cipher_ctx, ciphertext10, plaintext10,
                                      NUM_ROUNDS);
   small_aes_decrypt_rounds_always_mc(&cipher_ctx, ciphertext11, plaintext11,
                                      NUM_ROUNDS);

   utils::print_hex("P_10", plaintext10, SMALL_AES_NUM_STATE_BYTES);
   utils::print_hex("P_11", plaintext11, SMALL_AES_NUM_STATE_BYTES);
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static void
parse_args(ExperimentContext &context, int argc, const char **argv) {
    ArgumentParser parser;
    parser.appName("Falsifies that all 8-tuples are in delta-sets.");

    try {
        parser.parse((size_t) argc, argv);
    } catch (...) {
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(context, argc, argv);
    perform_experiment(context);
    return EXIT_SUCCESS;
}
