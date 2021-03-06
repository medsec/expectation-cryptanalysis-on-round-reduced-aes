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
#include "ciphers/aes_state.h"
#include "utils/argparse.h"
#include "utils/utils.h"
#include "utils/xorshift1024.h"


using ciphers::aes128_ctx_t;
using ciphers::aes_state_t;
using ciphers::aes128_key_t;
using ciphers::AESState;
using utils::xor_arrays;
using utils::compute_mean;
using utils::compute_variance;
using utils::ArgumentParser;
using utils::xorshift_prng_ctx_t;

// ---------------------------------------------------------

static const size_t NUM_TEXTS_IN_STRUCTURE = 1L << 32;
static const size_t NUM_CELL_VALUES = 256;

// ---------------------------------------------------------

typedef struct {
    aes128_key_t key;
    aes128_ctx_t cipher_ctx;
    size_t num_keys;
    size_t num_rounds;
    size_t num_structures_per_key;
    bool use_prp = false;
} ExperimentContext;

typedef std::vector<size_t> HistogramVector;
typedef std::vector<AESState> AESStatesVector;

// ---------------------------------------------------------

static void generate_base_plaintext(aes_state_t plaintext) {
    utils::get_random_bytes(plaintext, AES_NUM_STATE_BYTES);

    // Zeroize
    // 0 x x x
    // x 0 x x
    // x x 0 x
    // x x x 0
    plaintext[0] = 0;
    plaintext[5] = 0;
    plaintext[10] = 0;
    plaintext[15] = 0;
}

// ---------------------------------------------------------

static void
get_text_from_delta_set(aes_state_t base_text, const size_t i) {
    // Extract from i = [i0 i1 i2 i3]
    // i0 x  x  x
    // x  i1 x  x
    // x  x  i2 x
    // x  x  x  i3
    base_text[0] = (uint8_t)((i >> 24) & 0xFF);
    base_text[5] = (uint8_t)((i >> 16) & 0xFF);
    base_text[10] = (uint8_t)((i >> 8) & 0xFF);
    base_text[15] = (uint8_t)(i & 0xFF);
}

// ---------------------------------------------------------

static void encrypt(const aes128_ctx_t *aes_context,
                    const size_t num_rounds,
                    aes_state_t plaintext,
                    AESState &ciphertext) {
    aes128_encrypt_rounds_always_mc(
        aes_context, plaintext, ciphertext.state, num_rounds
    );
}

// ---------------------------------------------------------

static size_t extract_cell_value(const aes_state_t state) {
    return (size_t) state[0];
}

// ---------------------------------------------------------

static void add_to_num_occurrences(HistogramVector &histogram,
                                   const aes_state_t state) {
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
    aes128_ctx_t cipher_ctx = context->cipher_ctx;
    aes128_key_t key;

    utils::get_random_bytes(key, AES_128_NUM_KEY_BYTES);
    aes128_key_setup(&cipher_ctx, key);

    auto num_structures_per_key = context->num_structures_per_key;
    HistogramVector num_occurrences_vector(NUM_CELL_VALUES);

    for (size_t i = 0; i < num_structures_per_key; ++i) {
        aes_state_t plaintext;
        generate_base_plaintext(plaintext);
        init_histogram(num_occurrences_vector);

        for (size_t j = 0; j < NUM_TEXTS_IN_STRUCTURE; ++j) {
            AESState ciphertext;
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

static void perform_experiments(ExperimentContext *context) {
    for (size_t i = 0; i < context->num_keys; ++i) {
        perform_experiment(context);
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
        "Test for the AES five-round distinguisher that tests for"
        "the number of collisions in the first byte from structures with"
        "all pairs from the first plaintext diagonal active.");
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-s", "--num_structures_per_key", 1, false);
    parser.addArgument("-r", "--num_rounds", 1, false);

    try {
        parser.parse((size_t) argc, argv);

        context->num_structures_per_key = parser.retrieveAsLong("s");
        context->num_keys = parser.retrieveAsLong("k");
        context->num_rounds = parser.retrieveAsLong("r");
    } catch (...) {
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

    printf("#Rounds         %8zu\n", context->num_rounds);
    printf("#Keys           %8zu\n", context->num_keys);
    printf("#Sets/Key (log) %8zu\n", context->num_structures_per_key);
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(&context, argc, argv);
    perform_experiments(&context);
    return EXIT_SUCCESS;
}
