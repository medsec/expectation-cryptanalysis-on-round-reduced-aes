/**
 * __author__ = anonymous
 * __date__   = 2019-01
 * __copyright__ = CC0
 */
#include <array>
#include <vector>
#include <stdint.h>
#include <stdlib.h>

#include "ciphers/aes.h"
#include "ciphers/aes_state.h"
#include "utils/argparse.h"
#include "utils/utils.h"
#include "utils/xorshift1024.h"


using namespace ciphers;
using namespace utils;

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
} ExperimentContext;

typedef std::vector<AESState> AESStatesVector;

// ---------------------------------------------------------

static uint32_t to_uint32(const aes_state_t array, const size_t from_index) {
    return (array[from_index] << 24)
        | (array[from_index + 1] << 16)
        | (array[from_index + 2] <<  8)
        | (array[from_index + 3]);
}

// ---------------------------------------------------------

static uint32_t extract_column(const aes_state_t array, const size_t column_index) {
    const size_t from_index = 4 * column_index;
    return to_uint32(array, from_index);
}

// ---------------------------------------------------------

struct AESStateColumnSorter {
    explicit AESStateColumnSorter(const size_t sort_column_index) :
        sort_column_index(sort_column_index) {};

    bool operator() (const AESState& left, const AESState& right) const {
        return extract_column(left.state, sort_column_index) <
            extract_column(right.state, sort_column_index);
    }

    size_t sort_column_index;
};

// ---------------------------------------------------------

static void get_text_from_delta_set(aes_state_t base_text, const size_t i) {
    base_text[0] = (uint8_t)i;
}

// ---------------------------------------------------------

static void encrypt(const aes128_ctx_t* aes_context,
                    aes_state_t plaintext,
                    AESState& ciphertext) {
    aes128_encrypt_rounds(
        aes_context, plaintext, ciphertext.state, NUM_CONSIDERED_ROUNDS
    );
    __m128i c = loadu(ciphertext.state);
    c = aes_invert_shift_rows(c);
    storeu(ciphertext.state, c);
}

// ---------------------------------------------------------

static size_t find_num_collisions_for_column(AESStatesVector &ciphertexts,
                                             const size_t column_index) {
    AESStateColumnSorter sorter(column_index);
    std::sort(ciphertexts.begin(), ciphertexts.end(), sorter);

    size_t num_collisions = 0;
    size_t num_current_colliding_texts = 0;
    uint32_t previous = 0;
    aes_state_t previous_state;

    bool is_first = true;
    bool was_colliding = false;

    for (auto j = ciphertexts.begin(); j != ciphertexts.end(); ++j) {
        const AESState& ciphertext = *j;
        const uint32_t current = extract_column(ciphertext.state, column_index);

        if (is_first) {
            previous = current;
            memcpy(previous_state, ciphertext.state, AES_NUM_STATE_BYTES);
            is_first = false;
            continue;
        }

        if (current == previous) {
            print_hex("previous state", previous_state, AES_NUM_STATE_BYTES);
            print_hex("current  state", ciphertext.state, AES_NUM_STATE_BYTES);
            printf("column  %2zu: %08x\n", column_index, previous);
            printf("column  %2zu: %08x\n", column_index, current);
            num_current_colliding_texts++;
            was_colliding = true;
            continue;
        }

        if (was_colliding) {
            was_colliding = false;
            num_collisions += num_current_colliding_texts *
                (num_current_colliding_texts + 1) / 2;
            continue;
        }

        num_current_colliding_texts = 0;
        previous = current;
        memcpy(previous_state, ciphertext.state, AES_NUM_STATE_BYTES);
    }

    if (was_colliding) {
        num_collisions += num_current_colliding_texts *
                          (num_current_colliding_texts + 1) / 2;
    }

    return num_collisions;
}

// ---------------------------------------------------------

static size_t find_equal_columns(AESStatesVector& ciphertexts) {
    size_t num_collisions = 0;

    for (size_t i = 0; i < AES_128_NUM_COLUMNS; ++i) {
        num_collisions += find_num_collisions_for_column(ciphertexts, i);
    }

    return num_collisions;
}

// ---------------------------------------------------------

static void print_num_collisions(const size_t num_collisions) {
    printf("Collisions: %8zu\n", num_collisions);
}

// ---------------------------------------------------------

static size_t perform_experiment(ExperimentContext* context) {
    aes128_ctx_t aes_context = context->cipher_ctx;
    aes128_key_t key;

    utils::get_random_bytes(key, AES_128_NUM_KEY_BYTES);
    aes128_key_setup(&aes_context, key);

    size_t num_collisions = 0;

    for (size_t i = 0; i < context->num_sets_per_key; ++i) {
        AESStatesVector ciphertexts;
        aes_state_t plaintext;
        utils::get_random_bytes(plaintext, AES_NUM_STATE_BYTES);

        for (size_t j = 0; j < NUM_TEXTS_IN_DELTA_SET; ++j) {
            AESState ciphertext;
            get_text_from_delta_set(plaintext, j);
            encrypt(&aes_context, plaintext, ciphertext);
            ciphertexts.push_back(ciphertext);
        }

        num_collisions += find_equal_columns(ciphertexts);

        if (i % 1024 == 0) {
            printf("Tested %8zu sets. Collisions: %8zu\n", i, num_collisions);
        }
    }

    print_num_collisions(num_collisions);
    return num_collisions;
}

// ---------------------------------------------------------

static void perform_experiments(ExperimentContext* context) {
    size_t num_total_collisions = 0;
    for (size_t i = 0; i < context->num_keys; ++i) {
        const size_t num_collisions =
            perform_experiment(context);
        num_total_collisions += num_collisions;
        printf("Key: %4zu\n", i + 1);
        printf("Total Collisions: %8zu\n", num_total_collisions);
    }
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static void parse_args(ExperimentContext* context, int argc, const char** argv) {
    ArgumentParser parser;
    parser.appName("Test for the AES-128 four-round impossible-differential distinguisher.");
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-s", "--num_sets_per_key", 1, false);

    try {
        parser.parse(argc, argv);

        context->num_sets_per_key = parser.retrieveAsLong("s");
        context->num_keys = parser.retrieveAsLong("k");
    } catch( ... ) {
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

    printf("#Keys      %8zu\n", context->num_keys);
    printf("#Sets/Key  %8zu\n", context->num_sets_per_key);
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(&context, argc, argv);
    perform_experiments(&context);
    return EXIT_SUCCESS;
}
