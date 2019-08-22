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
#include "ciphers/small_aes_toy10_sbox.h"
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
using utils::ArgumentParser;
using utils::xorshift_prng_ctx_t;

// ---------------------------------------------------------

static const size_t NUM_CONSIDERED_ROUNDS = 4;
static const size_t NUM_TEXTS_IN_DELTA_SET = 16;

// ---------------------------------------------------------

typedef struct {
    small_aes_key_t key;
    small_aes_ctx_t cipher_ctx;
    size_t num_keys;
    size_t num_sets_per_key;
    bool use_prp = false;
    bool use_all_delta_sets_from_diagonal = false;
    std::vector<size_t> num_matches;
} ExperimentContext;

typedef struct {
    std::vector<size_t> num_collisions_per_set;
    size_t num_collisions;
} ExperimentResult;

typedef size_t (*experiment_function_t)(ExperimentContext *);

typedef std::vector<SmallState> SmallStatesVector;

// ---------------------------------------------------------

static void generate_base_plaintext(small_aes_state_t plaintext) {
    // Choose the last 3 bytes randomly
    utils::get_random_bytes(plaintext, SMALL_AES_NUM_STATE_BYTES);
}

// ---------------------------------------------------------

static void get_text_from_delta_set(small_aes_state_t base_text,
                                    const size_t i) {
    base_text[0] = (uint8_t) ((i << 4) & 0xF0);
}

// ---------------------------------------------------------

static void
generate_base_plaintext_in_diagonal(small_aes_state_t plaintext,
                                    const size_t set_index_in_diagonal,
                                    const size_t byte_index_in_diagonal) {
    if (byte_index_in_diagonal == 0) {
        plaintext[2] = (uint8_t) (((set_index_in_diagonal >> 8) & 0x0F) |
                                  (plaintext[2] & 0xF0));
        plaintext[5] = (uint8_t) ((set_index_in_diagonal & 0xF0) |
                                  (plaintext[5] & 0x0F));
        plaintext[7] = (uint8_t) ((set_index_in_diagonal & 0x0F) |
                                  (plaintext[7] & 0xF0));
    } else if (byte_index_in_diagonal == 1) {
        plaintext[0] = (uint8_t) (((set_index_in_diagonal >> 4) & 0xF0) |
                                  (plaintext[0] & 0x0F));
        plaintext[5] = (uint8_t) ((set_index_in_diagonal & 0xF0) |
                                  (plaintext[5] & 0x0F));
        plaintext[7] = (uint8_t) ((set_index_in_diagonal & 0x0F) |
                                  (plaintext[7] & 0xF0));
    } else if (byte_index_in_diagonal == 2) {
        plaintext[0] = (uint8_t) (((set_index_in_diagonal >> 4) & 0xF0) |
                                  (plaintext[0] & 0x0F));
        plaintext[2] = (uint8_t) (((set_index_in_diagonal >> 4) & 0x0F) |
                                  (plaintext[2] & 0xF0));
        plaintext[7] = (uint8_t) ((set_index_in_diagonal & 0x0F) |
                                  (plaintext[7] & 0xF0));
    } else if (byte_index_in_diagonal == 3) {
        plaintext[0] = (uint8_t) (((set_index_in_diagonal >> 4) & 0xF0) |
                                  (plaintext[0] & 0x0F));
        plaintext[2] = (uint8_t) (((set_index_in_diagonal >> 4) & 0x0F) |
                                  (plaintext[2] & 0xF0));
        plaintext[5] = (uint8_t) ((set_index_in_diagonal & 0xF0) |
                                  (plaintext[5] & 0x0F));
    }
}

// ---------------------------------------------------------

static void
get_text_from_diagonal_delta_set(small_aes_state_t plaintext,
                                 const size_t byte_index_in_diagonal,
                                 const size_t index_in_delta_set) {
    if (byte_index_in_diagonal == 0) {
        plaintext[0] = (uint8_t) ((plaintext[0] & 0x0F) |
                                  ((index_in_delta_set << 4) & 0xF0));
    } else if (byte_index_in_diagonal == 1) {
        plaintext[2] = (uint8_t) ((plaintext[2] & 0xF0) |
                                  (index_in_delta_set & 0x0F));
    } else if (byte_index_in_diagonal == 2) {
        plaintext[5] = (uint8_t) ((plaintext[5] & 0x0F) |
                                  ((index_in_delta_set << 4) & 0xF0));
    } else if (byte_index_in_diagonal == 3) {
        plaintext[7] = (uint8_t) ((plaintext[7] & 0xF0) |
                                  (index_in_delta_set & 0x0F));
    }
}

// ---------------------------------------------------------

static void encrypt(const small_aes_ctx_t *aes_context,
                    small_aes_state_t plaintext,
                    SmallState &ciphertext) {
    small_aes_toy10_sbox_encrypt_rounds_only_sbox_in_final(
        aes_context, plaintext, ciphertext.state, NUM_CONSIDERED_ROUNDS
    );
}

// ---------------------------------------------------------

bool has_zero_first_nibble(const small_aes_state_t state) {
    return ((state[0] & 0xF0) == 0);
}

// ---------------------------------------------------------

static size_t find_num_collisions(SmallStatesVector &ciphertexts) {
    const size_t num_texts = ciphertexts.size();
    size_t num_collisions = 0;
    small_aes_state_t temp;

    for (size_t i = 0; i != num_texts; ++i) {
        const SmallState left = ciphertexts[i];

        for (size_t j = i + 1; j != num_texts; ++j) {
            const SmallState right = ciphertexts[j];
            xor_arrays(temp, left.state, right.state,
                       SMALL_AES_NUM_STATE_BYTES);

            if (has_zero_first_nibble(temp)) {
                num_collisions++;
            }
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
    utils::print_hex("# Key", key, SMALL_AES_NUM_KEY_BYTES);

    size_t num_collisions = 0;

    for (size_t i = 0; i < context->num_sets_per_key; ++i) {
        SmallStatesVector ciphertexts;
        small_aes_state_t plaintext;
        generate_base_plaintext(plaintext);

        for (size_t j = 0; j < NUM_TEXTS_IN_DELTA_SET; ++j) {
            SmallState ciphertext;
            get_text_from_delta_set(plaintext, j);
            encrypt(&cipher_ctx, plaintext, ciphertext);
            ciphertexts.push_back(ciphertext);
        }

        num_collisions += find_num_collisions(ciphertexts);

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
    small_aes_ctx_t cipher_ctx = context->cipher_ctx;
    small_aes_key_t key;

    utils::get_random_bytes(key, SMALL_AES_NUM_KEY_BYTES);
    small_aes_key_setup(&cipher_ctx, key);
    utils::print_hex("# Key", key, SMALL_AES_NUM_KEY_BYTES);

    size_t num_collisions = 0;
    const size_t num_sets_in_diagonal = 1L << 12;
    const size_t num_bytes_in_diagonal = 4;

    small_aes_state_t plaintext;
    generate_base_plaintext(plaintext);

    for (size_t i = 0; i < num_sets_in_diagonal; ++i) {
        for (size_t m = 0; m < num_bytes_in_diagonal; ++m) {
            generate_base_plaintext_in_diagonal(plaintext, i, m);
            SmallStatesVector ciphertexts;

            for (size_t j = 0; j < NUM_TEXTS_IN_DELTA_SET; ++j) {
                SmallState ciphertext;
                get_text_from_diagonal_delta_set(plaintext, m, j);
                encrypt(&cipher_ctx, plaintext, ciphertext);
                ciphertexts.push_back(ciphertext);
            }

            num_collisions += find_num_collisions(ciphertexts);
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

static size_t perform_experiment_with_prp(ExperimentContext *context) {
    speck64_context_t cipher_ctx;
    speck64_96_key_t key;

    utils::get_random_bytes(key, SPECK_64_96_NUM_KEY_BYTES);
    utils::print_hex("# Key", key, SPECK_64_96_NUM_KEY_BYTES);
    speck64_96_key_schedule(&cipher_ctx, key);

    size_t num_collisions = 0;

    for (size_t i = 0; i < context->num_sets_per_key; ++i) {
        SmallStatesVector ciphertexts;
        speck64_state_t plaintext;
        generate_base_plaintext(plaintext);

        for (size_t j = 0; j < NUM_TEXTS_IN_DELTA_SET; ++j) {
            SmallState ciphertext;
            get_text_from_delta_set(plaintext, j);
            speck64_encrypt(&cipher_ctx, plaintext, ciphertext.state);
            ciphertexts.push_back(ciphertext);
        }

        num_collisions += find_num_collisions(ciphertexts);

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
    } else if (!context->use_prp &&
               !context->use_all_delta_sets_from_diagonal) {
        experiment_function = &perform_experiment;
    } else if (!context->use_prp && context->use_all_delta_sets_from_diagonal) {
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

static void parse_args(ExperimentContext *context,
                       int argc,
                       const char **argv) {
    ArgumentParser parser;
    parser.appName("Test for the Small-AES four-round distinguisher."
                   "If -d 1 -r 0 is set, uses all 4 * 2^12 * binom(16, 2) "
                   "delta-sets from diagonals, but only for the Small-AES, "
                   "not for the PRP.");
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-s", "--num_sets_per_key", 1, false);
    parser.addArgument("-r", "--use_random_function", 1, false);
    parser.addArgument("-d", "--use_diagonals", 1, false);

    try {
        parser.parse((size_t) argc, argv);

        context->num_sets_per_key = static_cast<const size_t>(1L
            << parser.retrieveAsLong("s"));
        context->num_keys = parser.retrieveAsLong("k");
        context->use_prp = (bool) parser.retrieveAsInt("r");
        context->use_all_delta_sets_from_diagonal = (bool) parser.retrieveAsInt(
            "d");
    } catch (...) {
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

    printf("#Keys           %8zu\n", context->num_keys);
    printf("#Sets/Key (log) %8zu\n", context->num_sets_per_key);
    printf("#Uses PRP       %8d\n", context->use_prp);
    printf("#Uses Diagonal  %8d\n", context->use_all_delta_sets_from_diagonal);
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(&context, argc, argv);
    perform_experiments(&context);
    return EXIT_SUCCESS;
}
