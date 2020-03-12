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
#include "ciphers/small_aes_m02_mc.h"
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
using ciphers::speck64_context_t;
using ciphers::speck64_96_key_t;
using ciphers::speck64_state_t;
using utils::xor_arrays;
using utils::ArgumentParser;
using utils::xorshift_prng_ctx_t;

// ---------------------------------------------------------

static const size_t NUM_TEXTS_IN_STRUCTURE = 1L << 16;
static const size_t NUM_CELL_VALUES = 16;

// ---------------------------------------------------------

typedef struct {
    small_aes_key_t key;
    small_aes_ctx_t cipher_ctx;
    size_t num_keys;
    size_t num_rounds;
    size_t num_structures_per_key;
    bool use_prp = false;
} ExperimentContext;

typedef std::vector<size_t> HistogramVector;
typedef std::vector<uint64_t> SmallStateVector;

// ---------------------------------------------------------

static void generate_base_plaintext(small_aes_state_t plaintext) {
    utils::get_random_bytes(plaintext, SMALL_AES_NUM_STATE_BYTES);

    // Zeroize
    // 0 x x x
    // x 0 x x
    // x x 0 x
    // x x x 0

    plaintext[0] &= 0x0F; // Set
    plaintext[2] &= 0xF0;
    plaintext[5] &= 0x0F;
    plaintext[7] &= 0xF0;
}

// ---------------------------------------------------------

static void
get_text_from_delta_set(small_aes_state_t base_text, const size_t i) {
    // Extract from i = [i0 i1 i2 i3]
    // i0 x  x  x
    // x  i1 x  x
    // x  x  i2 x
    // x  x  x  i3
    base_text[0] = (uint8_t)(((i >> 8) & 0xF0) | (base_text[0] & 0x0F));
    base_text[2] = (uint8_t)(((i >> 8) & 0x0F) | (base_text[2] & 0xF0));
    base_text[5] = (uint8_t)((i & 0xF0) | (base_text[5] & 0x0F));
    base_text[7] = (uint8_t)((i & 0x0F) | (base_text[7] & 0xF0));
}

// ---------------------------------------------------------

static void encrypt(const small_aes_ctx_t *aes_context,
                    const size_t num_rounds,
                    small_aes_state_t plaintext,
                    SmallState &ciphertext) {
    small_aes_m02_mc_encrypt_rounds_only_sbox_in_final(
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

static size_t extract_cell_value(const small_aes_state_t state) {
    return (size_t) (state[0] >> 4) & 0xF;
}

// ---------------------------------------------------------

static void add_to_num_occurrences(HistogramVector &histogram,
                                   const small_aes_state_t state) {
    const size_t value = extract_cell_value(state);
    histogram[value]++;
}

// ---------------------------------------------------------

static void init_histogram(HistogramVector &histogram) {
    std::fill(histogram.begin(), histogram.end(), 0);
}

// ---------------------------------------------------------

static size_t find_num_collisions(const HistogramVector &histogram) {
    size_t result = 0;

    for (const auto &value : histogram) {
        if (value < 2) {
            continue;
        }

        result += value * (value - 1);
    }

    return result / 2;
}

// ---------------------------------------------------------

static void perform_experiment(ExperimentContext *context) {
    small_aes_ctx_t cipher_ctx = context->cipher_ctx;
    small_aes_key_t correct_key;

    utils::get_random_bytes(correct_key, SMALL_AES_NUM_KEY_BYTES);
    small_aes_key_setup(&cipher_ctx, correct_key);

    auto num_structures_per_key = context->num_structures_per_key;
    HistogramVector num_occurrences_vector(NUM_CELL_VALUES);

    for (size_t i = 0; i < num_structures_per_key; ++i) {
        small_aes_state_t plaintext;
        generate_base_plaintext(plaintext);
        init_histogram(num_occurrences_vector);

        for (size_t j = 0; j < NUM_TEXTS_IN_STRUCTURE; ++j) {
            SmallState ciphertext;
            get_text_from_delta_set(plaintext, j);

            encrypt(&cipher_ctx, context->num_rounds, plaintext, ciphertext);
            add_to_num_occurrences(num_occurrences_vector, ciphertext.state);
        }

        const size_t num_collisions = find_num_collisions(
            num_occurrences_vector
        );
        printf("#Collisions: %6zu\n", num_collisions);
    }
}

// ---------------------------------------------------------

static void perform_experiment_prp(ExperimentContext *context) {
    speck64_context_t cipher_ctx;
    speck64_96_key_t key;

    utils::get_random_bytes(key, SPECK_64_96_NUM_KEY_BYTES);
    speck64_96_key_schedule(&cipher_ctx, key);

    auto num_structures_per_key = context->num_structures_per_key;

    HistogramVector num_occurrences_vector(NUM_CELL_VALUES);

    for (size_t i = 0; i < num_structures_per_key; ++i) {
        speck64_state_t plaintext;
        generate_base_plaintext(plaintext);
        init_histogram(num_occurrences_vector);

        for (size_t j = 0; j < NUM_TEXTS_IN_STRUCTURE; ++j) {
            speck64_state_t ciphertext;
            get_text_from_delta_set(plaintext, j);

            encrypt_prp(&cipher_ctx, plaintext, ciphertext);
            add_to_num_occurrences(num_occurrences_vector, ciphertext);
        }

        const size_t num_collisions = find_num_collisions(
            num_occurrences_vector
        );
        printf("#Collisions: %6zu\n", num_collisions);
    }
}

// ---------------------------------------------------------

static void perform_experiments(ExperimentContext *context) {
    for (size_t i = 0; i < context->num_keys; ++i) {
        if (context->use_prp) {
            perform_experiment_prp(context);
        } else {
            perform_experiment(context);
        }

        printf("%4zu/%4zu\n", i + 1, context->num_keys);
    }
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static void
parse_args(ExperimentContext *context, int argc, const char **argv) {
    ArgumentParser parser;
    parser.appName(
        "Test for the Small-AES five-round distinguisher that tests for"
        "the number of collisions in the first byte from structures with"
        "all pairs from the first plaintext diagonal active.");
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-s", "--num_structures_per_key", 1, false);
    parser.addArgument("-r", "--num_rounds", 1, false);
    parser.addArgument("-p", "--use_prp", 1, true);

    try {
        parser.parse((size_t) argc, argv);

        context->num_structures_per_key = parser.retrieveAsLong("s");
        context->num_keys = parser.retrieveAsLong("k");
        context->num_rounds = parser.retrieveAsLong("r");

        if (parser.wasSet("-p")) {
            context->use_prp = (bool)parser.retrieveAsInt("p");
        }
    } catch (...) {
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

    printf("#Rounds         %8zu\n", context->num_rounds);
    printf("#Keys           %8zu\n", context->num_keys);
    printf("#Sets/Key (log) %8zu\n", context->num_structures_per_key);
    printf("# PRP           %8d\n", context->use_prp);
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(&context, argc, argv);
    perform_experiments(&context);
    return EXIT_SUCCESS;
}
