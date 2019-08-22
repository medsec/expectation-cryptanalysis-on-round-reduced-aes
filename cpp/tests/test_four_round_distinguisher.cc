/**
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */


#include <array>
#include <vector>
#include <stdint.h>
#include <stdlib.h>

#include "ciphers/random_function.h"
#include "ciphers/aes.h"
#include "ciphers/aes_state.h"
#include "utils/argparse.h"
#include "utils/utils.h"
#include "utils/xorshift1024.h"


using ciphers::aes128_ctx_t;
using ciphers::aes_state_t;
using ciphers::aes128_key_t;
using ciphers::AESState;
using utils::assert_equal;
using utils::compute_mean;
using utils::compute_variance;
using utils::xor_arrays;
using utils::ArgumentParser;

// ---------------------------------------------------------

static const size_t NUM_CONSIDERED_ROUNDS = 4;
static const size_t NUM_TEXTS_IN_DELTA_SET = 256;

// ---------------------------------------------------------

typedef struct {
    aes128_key_t key;
    aes128_ctx_t cipher_ctx;
    size_t num_keys;
    size_t num_sets_per_key;
    std::vector<size_t> num_matches;
    bool use_all_delta_sets_from_diagonal = false;
} ExperimentContext;

typedef struct {
    std::vector<size_t> num_collisions_per_set;
    size_t num_collisions;
} ExperimentResult;

typedef size_t (*experiment_function_t)(ExperimentContext *);

typedef std::vector<AESState> AESStatesVector;

// ---------------------------------------------------------

static void
generate_base_plaintext(aes_state_t plaintext) {
    utils::get_random_bytes(plaintext, AES_NUM_STATE_BYTES);
    plaintext[0] = 0;
    plaintext[5] = 0;
    plaintext[10] = 0;
    plaintext[15] = 0;
}

// ---------------------------------------------------------

static void
get_text_from_delta_set(aes_state_t base_text, const size_t i) {
    base_text[0] = (uint8_t) i;
}

// ---------------------------------------------------------

static void
generate_base_plaintext_in_diagonal(aes_state_t plaintext,
                                    const size_t set_index_in_diagonal,
                                    const size_t byte_index_in_diagonal) {
    if (byte_index_in_diagonal == 0) {
        plaintext[5] = (uint8_t) ((set_index_in_diagonal >> 16) & 0xFF);
        plaintext[10] = (uint8_t) ((set_index_in_diagonal >> 8) & 0xFF);
        plaintext[15] = (uint8_t) (set_index_in_diagonal & 0xFF);
    } else if (byte_index_in_diagonal == 1) {
        plaintext[0] = (uint8_t) ((set_index_in_diagonal >> 16) & 0xFF);
        plaintext[10] = (uint8_t) ((set_index_in_diagonal >> 8) & 0xFF);
        plaintext[15] = (uint8_t) (set_index_in_diagonal & 0xFF);
    } else if (byte_index_in_diagonal == 2) {
        plaintext[0] = (uint8_t) ((set_index_in_diagonal >> 16) & 0xFF);
        plaintext[5] = (uint8_t) ((set_index_in_diagonal >> 8) & 0xFF);
        plaintext[15] = (uint8_t) (set_index_in_diagonal & 0xFF);
    } else if (byte_index_in_diagonal == 3) {
        plaintext[0] = (uint8_t) ((set_index_in_diagonal >> 16) & 0xFF);
        plaintext[5] = (uint8_t) ((set_index_in_diagonal >> 8) & 0xFF);
        plaintext[10] = (uint8_t) (set_index_in_diagonal & 0xFF);
    }
}

// ---------------------------------------------------------

static void
get_text_from_diagonal_delta_set(aes_state_t plaintext,
                                 const size_t byte_index_in_diagonal,
                                 const size_t index_in_delta_set) {
    if (byte_index_in_diagonal == 0) {
        plaintext[0] = (uint8_t) index_in_delta_set;
    } else if (byte_index_in_diagonal == 1) {
        plaintext[5] = (uint8_t) index_in_delta_set;
    } else if (byte_index_in_diagonal == 2) {
        plaintext[10] = (uint8_t) index_in_delta_set;
    } else if (byte_index_in_diagonal == 3) {
        plaintext[15] = (uint8_t) index_in_delta_set;
    }
}

// ---------------------------------------------------------

static void encrypt(const aes128_ctx_t *aes_context,
                    aes_state_t plaintext,
                    AESState &ciphertext) {
    aes128_encrypt_rounds_only_sbox_in_final(
        aes_context, plaintext, ciphertext.state, NUM_CONSIDERED_ROUNDS
    );
}

// ---------------------------------------------------------

static size_t find_num_collisions(const uint8_t first_bytes[256]) {
    size_t num_collisions = 0;
    
    for (size_t i = 0; i != 256; ++i) {
        const size_t num_values = first_bytes[i];

        if (num_values <= 1) {
            continue;
        }

        num_collisions += num_values * (num_values - 1) / 2;
    }

    return num_collisions;
}

// ---------------------------------------------------------

static void zeroize(uint8_t* array, const size_t num_values) {
    for (size_t i = 0; i < num_values; ++i) {
        array[i] = 0;
    }
}

// ---------------------------------------------------------

static size_t perform_experiment(ExperimentContext *context) {
    aes128_ctx_t cipher_ctx = context->cipher_ctx;
    aes128_key_t key;

    utils::get_random_bytes(key, AES_128_NUM_KEY_BYTES);
    aes128_key_setup(&cipher_ctx, key);
    utils::print_hex("# Key", key, AES_128_NUM_KEY_BYTES);

    size_t num_collisions = 0;
    uint8_t first_bytes[256];

    for (size_t i = 0; i < context->num_sets_per_key; ++i) {
        aes_state_t plaintext;
        generate_base_plaintext(plaintext);
        zeroize(first_bytes, 256);

        for (size_t j = 0; j < NUM_TEXTS_IN_DELTA_SET; ++j) {
            AESState ciphertext;
            get_text_from_delta_set(plaintext, j);
            encrypt(&cipher_ctx, plaintext, ciphertext);
            
            const uint8_t first_byte = ciphertext.state[0];
            first_bytes[first_byte]++;
        }

        num_collisions += find_num_collisions(first_bytes);

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

static size_t perform_experiment_from_diagonal(ExperimentContext *context) {
    aes128_ctx_t cipher_ctx = context->cipher_ctx;
    aes128_key_t key;

    utils::get_random_bytes(key, AES_128_NUM_KEY_BYTES);
    aes128_key_setup(&cipher_ctx, key);
    utils::print_hex("# Key", key, AES_128_NUM_KEY_BYTES);

    size_t num_collisions = 0;
    const size_t num_sets_in_diagonal = 1L << 24;
    const size_t num_bytes_in_diagonal = 4;

    aes_state_t plaintext;
    generate_base_plaintext(plaintext);
    uint8_t first_bytes[256];

    for (size_t i = 0; i < num_sets_in_diagonal; ++i) {
        for (size_t m = 0; m < num_bytes_in_diagonal; ++m) {
            generate_base_plaintext_in_diagonal(plaintext, i, m);
            zeroize(first_bytes, 256);

            for (size_t j = 0; j < NUM_TEXTS_IN_DELTA_SET; ++j) {
                AESState ciphertext;
                get_text_from_diagonal_delta_set(plaintext, m, j);
                encrypt(&cipher_ctx, plaintext, ciphertext);

                const uint8_t first_byte = ciphertext.state[0];
                first_bytes[first_byte]++;
            }

            num_collisions += find_num_collisions(first_bytes);
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

    if (!context->use_all_delta_sets_from_diagonal) {
        experiment_function = &perform_experiment;
    } else {
        experiment_function = &perform_experiment_from_diagonal;
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

        printf("%4zu %8zu %8.4f\n", i + 1, num_collisions, mean);
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

static void
parse_args(ExperimentContext *context, int argc, const char **argv) {
    ArgumentParser parser;
    parser.appName("Test for the Small-AES four-round distinguisher."
                   "If -d 1 is set, uses all 4 * 2^24 * binom(256, 2) "
                   "delta-sets from diagonals.");
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-s", "--num_sets_per_key", 1, false);
    parser.addArgument("-d", "--use_diagonals", 1, false);

    try {
        parser.parse((size_t) argc, argv);

        context->num_sets_per_key = static_cast<const size_t>(1L
            << parser.retrieveAsLong("s"));
        context->num_keys = parser.retrieveAsLong("k");
        context->use_all_delta_sets_from_diagonal = (bool) parser.retrieveAsInt(
            "d");
    } catch (...) {
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

    printf("#Keys           %8zu\n", context->num_keys);
    printf("#Sets/Key (log) %8zu\n", context->num_sets_per_key);
    printf("#Uses Diagonal  %8d\n", context->use_all_delta_sets_from_diagonal);
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(&context, argc, argv);
    perform_experiments(&context);
    return EXIT_SUCCESS;
}
