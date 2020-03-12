/**
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */
#include <stdint.h>
#include <stdlib.h>
#include <array>
#include <vector>

#include "ciphers/random_function.h"
#include "ciphers/small_aes.h"
#include "ciphers/small_state.h"
#include "ciphers/speck64.h"
#include "utils/argparse.h"
#include "utils/utils.h"
#include "utils/xorshift1024.h"


using ciphers::small_aes_ctx_t;
using ciphers::small_aes_state_t;
using ciphers::small_aes_key_t;
using ciphers::SmallState;
using ciphers::speck64_context_t;
using ciphers::speck64_96_key_t;
using ciphers::speck64_state_t;
using utils::xor_arrays;
using utils::compute_mean;
using utils::compute_variance;
using utils::to_uint64;
using utils::ArgumentParser;
using utils::xorshift_prng_ctx_t;

// ---------------------------------------------------------

static const size_t NUM_PAIRS = 4;

// ---------------------------------------------------------

typedef struct {
    small_aes_key_t key;
    small_aes_ctx_t cipher_ctx;
    size_t num_keys;
    size_t num_rounds;
    size_t num_sets_per_key;
    bool use_prp = false;
    size_t num_collisions = 0;
    size_t structure_start_index = 0;
} ExperimentContext;

typedef struct {
    std::vector<size_t> num_collisions_per_set;
    size_t num_collisions;
} ExperimentResult;

typedef size_t (*experiment_function_t)(ExperimentContext *);

// ---------------------------------------------------------

static void
generate_base_plaintexts(uint8_t *plaintexts, const size_t num_bytes) {
    utils::get_random_bytes(plaintexts, num_bytes);
}

// ---------------------------------------------------------

static void
generate_base_plaintext(small_aes_state_t plaintext) {
    utils::get_random_bytes(plaintext, SMALL_AES_NUM_STATE_BYTES);
}

// ---------------------------------------------------------

static void
get_plaintexts_prime(uint8_t *plaintexts,
                     uint8_t *random_bytes,
                     const size_t num_pairs) {
    // Sample until to ensure that the plaintexts P' will not collide with
    // the plaintexts P

    utils::get_random_bytes(random_bytes, 2 * num_pairs);

    for (size_t i = 0; i < num_pairs; ++i) {
        while ((random_bytes[2 * i] == 0) && (random_bytes[2 * i + 1] == 0)) {
            utils::get_random_bytes(&(random_bytes[2 * i]), 2);
        }
    }

    for (size_t i = 0; i < num_pairs; ++i) {
        size_t plaintext_start = i * SMALL_AES_NUM_STATE_BYTES;

        plaintexts[plaintext_start + 0] ^= random_bytes[0] & 0xF0;
        plaintexts[plaintext_start + 2] ^= random_bytes[0] & 0x0F;
        plaintexts[plaintext_start + 5] ^= random_bytes[1] & 0xF0;
        plaintexts[plaintext_start + 7] ^= random_bytes[1] & 0x0F;
    }
}

// ---------------------------------------------------------

static void
get_plaintext_prime(small_aes_state_t plaintexts,
                    uint8_t *random_bytes) {
    // Sample until to ensure that the plaintexts P' will not collide with
    // the plaintexts P
    do {
        utils::get_random_bytes(random_bytes, 2);
    } while ((random_bytes[0] == 0) && (random_bytes[1] == 0));

    plaintexts[0] ^= random_bytes[0] & 0xF0;
    plaintexts[2] ^= random_bytes[0] & 0x0F;
    plaintexts[5] ^= random_bytes[1] & 0xF0;
    plaintexts[7] ^= random_bytes[1] & 0x0F;
}

// ---------------------------------------------------------

static inline void encrypt(const small_aes_ctx_t *aes_context,
                           const uint8_t *plaintexts,
                           uint8_t *ciphertexts,
                           const size_t num_rounds) {
    small_aes_encrypt_rounds_4_only_sbox_in_final(
        aes_context, plaintexts, ciphertexts, num_rounds
    );
}

// ---------------------------------------------------------

static bool collide_in_column(const uint8_t *ciphertext_1,
                              const uint8_t *ciphertext_2) {
    return (ciphertext_1[0] == ciphertext_2[0])
           && (ciphertext_1[1] == ciphertext_2[1]);
}

// ---------------------------------------------------------

static size_t find_num_collisions(const uint8_t *ciphertexts_1,
                                  const uint8_t *ciphertexts_2,
                                  const size_t num_pairs) {
    size_t num_collisions = 0;
    size_t offset = 0;

    for (size_t i = 0; i < num_pairs; ++i) {
        offset = i * SMALL_AES_NUM_STATE_BYTES;

        if (collide_in_column(ciphertexts_1 + offset,
                              ciphertexts_2 + offset)) {
            num_collisions++;
        }
    }

    return num_collisions;
}

// ---------------------------------------------------------

static size_t perform_experiment(ExperimentContext *context) {
    small_aes_ctx_t cipher_ctx = context->cipher_ctx;
    small_aes_key_t key;

    utils::get_random_bytes(key, SMALL_AES_NUM_KEY_BYTES);
    small_aes_key_setup(&cipher_ctx, key);
    small_aes_key_setup_4(&cipher_ctx);
    utils::print_hex("# Key", key, SMALL_AES_NUM_KEY_BYTES);
    utils::print_256("# 4 concatenated Keys K^0", cipher_ctx.key_4[0]);

    const size_t num_bytes = SMALL_AES_NUM_STATE_BYTES * NUM_PAIRS;
    const size_t num_sets_per_key = context->num_sets_per_key / NUM_PAIRS;
    size_t num_collisions = 0;

    uint8_t random_bytes[2 * NUM_PAIRS];
    uint8_t plaintexts_1[num_bytes];
    uint8_t plaintexts_2[num_bytes];
    uint8_t ciphertexts_1[num_bytes];
    uint8_t ciphertexts_2[num_bytes];

    for (size_t i = 0; i < num_sets_per_key; ++i) {
        generate_base_plaintexts(plaintexts_1, num_bytes);
        memcpy(plaintexts_2, plaintexts_1, num_bytes);
        get_plaintexts_prime(plaintexts_2,
                             random_bytes,
                             NUM_PAIRS);

        encrypt(&cipher_ctx, plaintexts_1, ciphertexts_1, context->num_rounds);
        encrypt(&cipher_ctx, plaintexts_2, ciphertexts_2, context->num_rounds);

        num_collisions += find_num_collisions(ciphertexts_1,
                                              ciphertexts_2,
                                              NUM_PAIRS);

        if (i > 0) {
            if ((i & 0xFFFFF) == 0) {
                printf("# Tested %8zu sets. Collisions: %8zu\n", i * NUM_PAIRS,
                       num_collisions);
            }
        }
    }

    return num_collisions;
}

// ---------------------------------------------------------

static size_t perform_experiment_with_prp(ExperimentContext *context) {
    speck64_context_t cipher_ctx;
    speck64_96_key_t key;

    utils::get_random_bytes(key, SPECK_64_96_NUM_KEY_BYTES);
    utils::print_hex("# Key", key, SPECK_64_96_NUM_KEY_BYTES);
    speck64_96_key_schedule(&cipher_ctx, key);

    size_t num_collisions = 0;
    uint8_t random_bytes[2];

    for (size_t i = 0; i < context->num_sets_per_key; ++i) {
        speck64_state_t plaintext;
        speck64_state_t plaintext_2;

        generate_base_plaintext(plaintext);
        memcpy(plaintext_2, plaintext, SMALL_AES_NUM_STATE_BYTES);
        get_plaintext_prime(plaintext_2, random_bytes);

        speck64_state_t ciphertext;
        speck64_state_t ciphertext_2;

        speck64_encrypt(&cipher_ctx, plaintext, ciphertext);
        speck64_encrypt(&cipher_ctx, plaintext_2, ciphertext_2);

        if (collide_in_column(ciphertext, ciphertext_2)) {
            num_collisions++;
        }

        if (i > 0) {
            if ((i & 0xFFFFF) == 0) {
                printf("# Tested %8zu sets. Collisions: %8zu\n", i,
                       num_collisions);
            }
        }
    }

    return num_collisions;
}

// ---------------------------------------------------------

static void perform_experiments(ExperimentContext *context) {
    experiment_function_t experiment_function = nullptr;

    if (context->use_prp) {
        experiment_function = &perform_experiment_with_prp;
    } else {
        experiment_function = &perform_experiment;
    }

    ExperimentResult all_results;
    all_results.num_collisions = 0;

    printf("#%8zu Experiments\n", context->num_keys);
    printf("#%8zu Sets/key\n", context->num_sets_per_key);
    printf("# Key Collisions Mean Variance \n");

    for (size_t i = 0; i < context->num_keys; ++i) {
        const size_t num_collisions = experiment_function(context);
        const double mean =
            (double) num_collisions / (double) context->num_sets_per_key;

        all_results.num_collisions += num_collisions;
        all_results.num_collisions_per_set.push_back(num_collisions);

        printf("%4zu %8zu %f\n", i + 1, num_collisions, mean);
    }

    const double mean = compute_mean(all_results.num_collisions_per_set);
    const double variance = compute_variance(
        all_results.num_collisions_per_set);

    printf("# Total Keys Collisions Mean Variance \n");

    printf("# %4zu %8zu %8.4f %8.8f\n",
           context->num_keys,
           all_results.num_collisions,
           mean,
           variance);
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static void parse_args(ExperimentContext *context,
                       int argc,
                       const char **argv) {
    ArgumentParser parser;
    parser.appName("Test for the Small-AES r-round distinguisher for columns.");
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-s", "--num_sets_per_key", 1, false);
    parser.addArgument("-p", "--use_random_function", 1, false);
    parser.addArgument("-r", "--num_rounds", 1, false);

    try {
        parser.parse((size_t) argc, argv);

        context->num_sets_per_key = static_cast<const size_t>(1L
            << parser.retrieveAsLong("s"));
        context->num_keys = parser.retrieveAsLong("k");
        context->num_rounds = parser.retrieveAsLong("r");
        context->use_prp = (bool) parser.retrieveAsInt("p");
    } catch (...) {
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

    printf("#Rounds         %8zu\n", context->num_rounds);
    printf("#Keys           %8zu\n", context->num_keys);
    printf("#Sets/Key (log) %8zu\n", context->num_sets_per_key);
    printf("#Uses PRP       %8d\n", context->use_prp);
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(&context, argc, argv);
    perform_experiments(&context);
    return EXIT_SUCCESS;
}
