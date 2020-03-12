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
#include "ciphers/small_state.h"
#include "ciphers/small_state_pair.h"
#include "ciphers/speck64.h"
#include "utils/argparse.h"
#include "utils/utils.h"
#include "utils/xorshift1024.h"


using ciphers::small_aes_ctx_t;
using ciphers::small_aes_state_t;
using ciphers::small_aes_key_t;
using ciphers::SmallState;
using ciphers::SmallStatePair;
using ciphers::speck64_context_t;
using ciphers::speck64_96_key_t;
using ciphers::speck64_state_t;
using utils::compute_mean;
using utils::compute_variance;
using utils::xor_arrays;
using utils::ArgumentParser;
using utils::xorshift_prng_ctx_t;

// ---------------------------------------------------------

static const size_t NUM_TEXTS_IN_STRUCTURE = 1 << 16;

// ---------------------------------------------------------

typedef struct {
    small_aes_key_t key;
    small_aes_ctx_t cipher_ctx;
    size_t num_keys;
    size_t num_rounds;
    size_t num_sets_per_key;
    size_t input_diagonal_index;
    size_t output_diagonal_index;
    bool use_prp = false;
} ExperimentContext;

typedef std::vector<size_t> UInt64Vector;

typedef struct {
    UInt64Vector num_collisions_per_set;
    size_t num_collisions;
} ExperimentResult;

// ---------------------------------------------------------

static void generate_base_plaintext(small_aes_state_t plaintext,
                                    const size_t index,
                                    const size_t input_diagonal_index) {
    (void) index;
    utils::get_random_bytes(plaintext, SMALL_AES_NUM_STATE_BYTES);

    // Zeroize
    // 0 x x x
    // x 0 x x
    // x x 0 x
    // x x x 0

    if (input_diagonal_index == 0) {
        plaintext[0] &= 0x0F;
        plaintext[2] &= 0xF0;
        plaintext[5] &= 0x0F;
        plaintext[7] &= 0xF0;
    } else if (input_diagonal_index == 1) {
        plaintext[2] &= 0x0F;
        plaintext[4] &= 0xF0;
        plaintext[7] &= 0x0F;
        plaintext[1] &= 0xF0;
    } else if (input_diagonal_index == 2) {
        plaintext[4] &= 0x0F;
        plaintext[6] &= 0xF0;
        plaintext[1] &= 0x0F;
        plaintext[3] &= 0xF0;
    } else if (input_diagonal_index == 3) {
        plaintext[6] &= 0x0F;
        plaintext[0] &= 0xF0;
        plaintext[3] &= 0x0F;
        plaintext[5] &= 0xF0;
    }
}

// ---------------------------------------------------------

static void
get_text_from_delta_set(small_aes_state_t base_text,
                        const size_t i,
                        const size_t input_diagonal_index) {
    // Extract from i = [i0 i1 i2 i3]
    // i0 x  x  x
    // x  i1 x  x
    // x  x  i2 x
    // x  x  x  i3
    if (input_diagonal_index == 0) {
        base_text[0] = (uint8_t) ((i >> 8) & 0xF0);
        base_text[2] = (uint8_t) ((i >> 8) & 0x0F);
        base_text[5] = (uint8_t) (i & 0xF0);
        base_text[7] = (uint8_t) (i & 0x0F);
    } else if (input_diagonal_index == 1) {
        base_text[2] = (uint8_t) ((i >> 8) & 0xF0);
        base_text[4] = (uint8_t) ((i >> 8) & 0x0F);
        base_text[7] = (uint8_t) (i & 0xF0);
        base_text[1] = (uint8_t) (i & 0x0F);
    } else if (input_diagonal_index == 2) {
        base_text[4] = (uint8_t) ((i >> 8) & 0xF0);
        base_text[6] = (uint8_t) ((i >> 8) & 0x0F);
        base_text[1] = (uint8_t) (i & 0xF0);
        base_text[3] = (uint8_t) (i & 0x0F);
    } else if (input_diagonal_index == 3) {
        base_text[6] = (uint8_t) ((i >> 8) & 0xF0);
        base_text[0] = (uint8_t) ((i >> 8) & 0x0F);
        base_text[3] = (uint8_t) (i & 0xF0);
        base_text[5] = (uint8_t) (i & 0x0F);
    }
}

// ---------------------------------------------------------

static void encrypt(const small_aes_ctx_t *aes_context,
                    const size_t num_rounds,
                    small_aes_state_t plaintext,
                    SmallState &ciphertext) {
    small_aes_encrypt_rounds_only_sbox_in_final(
        aes_context, plaintext, ciphertext.state, num_rounds
    );
}

// ---------------------------------------------------------

static void encrypt_prp(const speck64_context_t *speck64_context,
                        speck64_state_t plaintext,
                        speck64_state_t ciphertext) {
    speck64_encrypt(speck64_context, plaintext, ciphertext);
}

// ---------------------------------------------------------

static size_t extract_column_value(const small_aes_state_t state,
                                   const size_t output_diagonal_index) {
    if (output_diagonal_index == 0) {
        return (size_t) ((state[0] << 8) | state[1]);
    }

    if (output_diagonal_index == 1) {
        return (size_t) ((state[2] << 8) | state[3]);
    }

    if (output_diagonal_index == 2) {
        return (size_t) ((state[4] << 8) | state[5]);
    }

    return (size_t) ((state[6] << 8) | state[7]);
}

// ---------------------------------------------------------

static void add_to_num_occurrences(UInt64Vector &histogram,
                                   const small_aes_state_t state,
                                   const size_t output_diagonal_index) {
    const size_t value = extract_column_value(state, output_diagonal_index);
    histogram[value]++;
}

// ---------------------------------------------------------

static void init_histogram(UInt64Vector &histogram) {
    std::fill(histogram.begin(), histogram.end(), 0);
}

// ---------------------------------------------------------

static size_t find_num_collisions(const UInt64Vector &histogram) {
    size_t result = 0;

    for (const auto &value : histogram) {
        if (value < 2) {
            continue;
        }

        result += value * (value - 1) / 2;
    }

    return result;
}

// ---------------------------------------------------------

static size_t perform_experiment(ExperimentContext *context) {
    small_aes_ctx_t cipher_ctx = context->cipher_ctx;
    small_aes_key_t correct_key;

    utils::get_random_bytes(correct_key, SMALL_AES_NUM_KEY_BYTES);
    small_aes_key_setup(&cipher_ctx, correct_key);

    auto num_sets_per_key = context->num_sets_per_key;
    size_t num_total_collisions = 0;

    for (size_t i = 0; i < num_sets_per_key; ++i) {
        UInt64Vector num_occurrences_vector(NUM_TEXTS_IN_STRUCTURE);
        init_histogram(num_occurrences_vector);

        small_aes_state_t plaintext;
        generate_base_plaintext(plaintext, i, context->input_diagonal_index);

        for (size_t j = 0; j < NUM_TEXTS_IN_STRUCTURE; ++j) {
            SmallState ciphertext;
            get_text_from_delta_set(plaintext,
                                    j,
                                    context->input_diagonal_index);

            encrypt(&cipher_ctx, context->num_rounds, plaintext, ciphertext);
            add_to_num_occurrences(num_occurrences_vector,
                                   ciphertext.state,
                                   context->output_diagonal_index);
        }

        const size_t num_collisions = find_num_collisions(
            num_occurrences_vector);
        num_total_collisions += num_collisions;

        printf("# %8zu %8zu\n", i, num_collisions);
    }

    return num_total_collisions;
}

// ---------------------------------------------------------

static size_t perform_experiment_prp(ExperimentContext *context) {
    speck64_context_t cipher_ctx;
    speck64_96_key_t key;

    utils::get_random_bytes(key, SPECK_64_96_NUM_KEY_BYTES);
    speck64_96_key_schedule(&cipher_ctx, key);

    auto num_sets_per_key = context->num_sets_per_key;
    size_t num_total_collisions = 0;

    for (size_t i = 0; i < num_sets_per_key; ++i) {
        UInt64Vector num_occurrences_vector(NUM_TEXTS_IN_STRUCTURE);
        init_histogram(num_occurrences_vector);

        speck64_state_t plaintext;
        generate_base_plaintext(plaintext, i, context->input_diagonal_index);

        for (size_t j = 0; j < NUM_TEXTS_IN_STRUCTURE; ++j) {
            speck64_state_t ciphertext;
            get_text_from_delta_set(plaintext,
                                    j,
                                    context->input_diagonal_index);

            encrypt_prp(&cipher_ctx, plaintext, ciphertext);
            add_to_num_occurrences(num_occurrences_vector, ciphertext,
                                   context->output_diagonal_index);
        }

        const size_t num_collisions = find_num_collisions(
            num_occurrences_vector);
        num_total_collisions += num_collisions;

        printf("# %8zu %8zu\n", i, num_collisions);
    }

    return num_total_collisions;
}


// ---------------------------------------------------------

static void perform_experiments(ExperimentContext *context) {
    ExperimentResult all_results;
    all_results.num_collisions = 0;

    printf("#%8zu Experiments\n", context->num_keys);
    printf("#%8zu Sets/key\n", context->num_sets_per_key);
    printf("# Key Collisions Mean Variance \n");

    for (size_t i = 0; i < context->num_keys; ++i) {
        size_t num_collisions = 0;

        if (context->use_prp) {
            num_collisions = perform_experiment_prp(context);
        } else {
            num_collisions = perform_experiment(context);
        }

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
    parser.appName(
        "Test for the Small-AES r-round distinguisher that tests for"
        "the number of collisions in the i-th column from structures with"
        "the o-th diagonal active.");
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-s", "--num_sets_per_key", 1, false);
    parser.addArgument("-r", "--num_rounds", 1, false);
    parser.addArgument("-p", "--use_prp", 1, false);
    parser.addArgument("-i", "--input_diagonal_index", 1, false);
    parser.addArgument("-o", "--output_diagonal_index", 1, false);

    try {
        parser.parse((size_t) argc, argv);

        context->num_sets_per_key = static_cast<const size_t>(1L
            << parser.retrieveAsLong("s"));
        context->num_keys = parser.retrieveAsLong("k");
        context->num_rounds = parser.retrieveAsLong("r");
        context->input_diagonal_index = parser.retrieveAsLong("i");
        context->output_diagonal_index = parser.retrieveAsLong("o");
        context->use_prp = (bool) parser.retrieveAsInt("p");
    } catch (...) {
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

    printf("#Rounds         %8zu\n", context->num_rounds);
    printf("#Keys           %8zu\n", context->num_keys);
    printf("#Sets/Key (log) %8zu\n", context->num_sets_per_key);
    printf("#Input index    %8zu\n", context->input_diagonal_index);
    printf("#Output index   %8zu\n", context->output_diagonal_index);
    printf("#Uses PRP       %8d\n", context->use_prp);
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(&context, argc, argv);
    perform_experiments(&context);
    return EXIT_SUCCESS;
}
