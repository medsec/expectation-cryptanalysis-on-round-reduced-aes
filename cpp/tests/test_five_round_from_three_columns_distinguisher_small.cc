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
using utils::ArgumentParser;
using utils::xorshift_prng_ctx_t;

// ---------------------------------------------------------

static const size_t NUM_CONSIDERED_ROUNDS = 5;
static const size_t NUM_TEXTS_IN_DELTA_SET = 1L << 16;

// ---------------------------------------------------------

typedef struct {
    small_aes_key_t key;
    small_aes_ctx_t cipher_ctx;
    xorshift_prng_ctx_t xorshift_ctx;
    size_t num_keys;
    size_t num_sets_per_key;
    std::vector<size_t> num_matches;
    bool use_prp = false;
} ExperimentContext;

typedef std::vector<SmallState> SmallStatesVector;

// ---------------------------------------------------------

static void generate_base_plaintext(small_aes_state_t plaintext) {
    // Use randomly
    utils::get_random_bytes(plaintext, SMALL_AES_NUM_STATE_BYTES);
}

// ---------------------------------------------------------

static void get_text_from_delta_set(small_aes_state_t base_text,
                                    xorshift_prng_ctx_t* xorshift_context) {
    // We use random
    // xxx0
    // 0xxx
    // x0xx
    // xx0x

    const uint8_t static_bytes[4] = {
        base_text[0], base_text[3], base_text[5], base_text[6]
    };
    utils::get_random_bytes(xorshift_context, base_text, 8);
    base_text[0] = (uint8_t)((base_text[0] & 0xF0) | (static_bytes[0] & 0x0F));
    base_text[3] = (uint8_t)((base_text[3] & 0x0F) | (static_bytes[1] & 0xF0));
    base_text[5] = (uint8_t)((base_text[5] & 0xF0) | (static_bytes[2] & 0x0F));
    base_text[6] = (uint8_t)((base_text[6] & 0x0F) | (static_bytes[3] & 0xF0));
}

// ---------------------------------------------------------

static void encrypt(const small_aes_ctx_t* aes_context,
                    small_aes_state_t plaintext,
                    SmallState& ciphertext) {
    small_aes_encrypt_rounds_only_sbox_in_final(
        aes_context, plaintext, ciphertext.state, NUM_CONSIDERED_ROUNDS
    );
}

// ---------------------------------------------------------

bool has_zero_column(const small_aes_state_t state) {
    return ((state[0] == 0) && (state[1] == 0))
        || ((state[2] == 0) && (state[3] == 0))
        || ((state[4] == 0) && (state[5] == 0))
        || ((state[6] == 0) && (state[7] == 0));
}

// ---------------------------------------------------------

static size_t find_num_collisions(SmallStatesVector& ciphertexts) {
    const size_t num_texts = ciphertexts.size();
    size_t num_collisions = 0;
    small_aes_state_t temp;

    for (size_t i = 0; i != num_texts; ++i) {
        const SmallState left = ciphertexts[i];

        for (size_t j = i + 1; j != num_texts; ++j) {
            const SmallState right = ciphertexts[j];
            xor_arrays(temp, left.state, right.state, SMALL_AES_NUM_STATE_BYTES);

            if (has_zero_column(temp)) {
                num_collisions++;
            }
        }
    }

    return num_collisions;
}

// ---------------------------------------------------------

static size_t perform_experiment(ExperimentContext* context) {
    small_aes_ctx_t cipher_ctx = context->cipher_ctx;
    small_aes_key_t key;

    utils::xorshift1024_init(&(context->xorshift_ctx));
    utils::get_random_bytes(key, SMALL_AES_NUM_KEY_BYTES);
    small_aes_key_setup(&cipher_ctx, key);

    size_t num_collisions = 0;

    for (size_t i = 0; i < context->num_sets_per_key; ++i) {
        SmallStatesVector ciphertexts;
        small_aes_state_t plaintext;
        generate_base_plaintext(plaintext);

        for (size_t j = 0; j < NUM_TEXTS_IN_DELTA_SET; ++j) {
            SmallState ciphertext;
            get_text_from_delta_set(plaintext, &(context->xorshift_ctx));
            encrypt(&cipher_ctx, plaintext, ciphertext);
            ciphertexts.push_back(ciphertext);
        }

        num_collisions += find_num_collisions(ciphertexts);

        if (i > 0) {
            if ((i & 0xFFFFF) == 0) {
                printf("Tested %8zu sets. Collisions: %8zu\n", i,
                       num_collisions);
            }
        }
    }

    return num_collisions;
}

// ---------------------------------------------------------

static size_t perform_experiment_with_prp(ExperimentContext* context) {
    speck64_context_t cipher_ctx;
    speck64_96_key_t key;

    utils::xorshift1024_init(&(context->xorshift_ctx));
    utils::get_random_bytes(key, SPECK_64_96_NUM_KEY_BYTES);
    speck64_96_key_schedule(&cipher_ctx, key);

    size_t num_collisions = 0;

    for (size_t i = 0; i < context->num_sets_per_key; ++i) {
        SmallStatesVector ciphertexts;
        speck64_state_t plaintext;
        generate_base_plaintext(plaintext);

        for (size_t j = 0; j < NUM_TEXTS_IN_DELTA_SET; ++j) {
            SmallState ciphertext;
            get_text_from_delta_set(plaintext, &(context->xorshift_ctx));
            speck64_encrypt(&cipher_ctx, plaintext, ciphertext.state);
            ciphertexts.push_back(ciphertext);
        }

        num_collisions += find_num_collisions(ciphertexts);

        if (i > 0) {
            if ((i & 0xFFFFF) == 0) {
                printf("Tested %8zu sets. Collisions: %8zu\n", i,
                       num_collisions);
            }
        }
    }

    return num_collisions;
}

// ---------------------------------------------------------

static void perform_experiments(ExperimentContext* context) {
    std::vector<size_t> collisions_vector;
    size_t num_total_collisions = 0;

    if (context->use_prp) {
        for (size_t i = 0; i < context->num_keys; ++i) {
            const size_t num_collisions = perform_experiment_with_prp(context);
            num_total_collisions += num_collisions;
            collisions_vector.push_back(num_collisions);

            const double num_collisions_per_key =
                (double)num_total_collisions / (i + 1);

            printf("Keys: %4zu Collisions %8zu Average %8.4f\n",
                   i + 1,
                   num_collisions,
                   num_collisions_per_key);
        }
    } else {
        for (size_t i = 0; i < context->num_keys; ++i) {
            const size_t num_collisions = perform_experiment(context);
            num_total_collisions += num_collisions;
            collisions_vector.push_back(num_collisions);

            const double num_collisions_per_key =
                (double)num_total_collisions / (i + 1);

            printf("Keys: %4zu Collisions %8zu Average %8.4f\n",
                   i + 1,
                   num_collisions,
                   num_collisions_per_key);
        }
    }
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static void parse_args(ExperimentContext* context, int argc, const char** argv) {
    ArgumentParser parser;
    parser.appName("Test for the Small-AES five-round distinguisher.");
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-s", "--num_sets_per_key", 1, false);
    parser.addArgument("-r", "--use_random_function", 1, false);

    try {
        parser.parse((size_t)argc, argv);

        context->num_sets_per_key = parser.retrieveAsLong("s");
        context->num_keys = parser.retrieveAsLong("k");
        context->use_prp = (bool)parser.retrieveAsInt("r");
    } catch( ... ) {
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

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
