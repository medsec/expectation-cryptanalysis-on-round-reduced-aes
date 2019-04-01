/**
 * __author__ = anonymous
 * __date__   = 2019-01
 * __copyright__ = CC0
 */
#include <map>
#include <vector>

#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#include "ciphers/small_aes.h"
#include "ciphers/small_state.h"
#include "ciphers/small_state_pair.h"
#include "utils/argparse.h"
#include "utils/utils.h"
#include "utils/xorshift1024.h"


using namespace ciphers;
using namespace utils;

// ---------------------------------------------------------
// Constants
// ---------------------------------------------------------

const size_t NUM_TEXTS_PER_STRUCTURE = 1 << 16;
const size_t NUM_CONSIDERED_ROUNDS = 5;

// ---------------------------------------------------------
// Types
// ---------------------------------------------------------

typedef std::vector<std::vector<SmallStatePair> > ColumnToPairsList;
typedef std::vector<SmallState> SmallStatesVector;
typedef std::pair<size_t, size_t> IntegerPair;

typedef struct {
    small_aes_key_t key;
    small_aes_ctx_t cipher_ctx;
    size_t num_keys;
    size_t num_structures_per_key;
    size_t num_delta_set_collisions;
    size_t num_non_delta_set_collisions;
    ColumnToPairsList list0;
    ColumnToPairsList list1;
    ColumnToPairsList list2;
    ColumnToPairsList list3;
} ExperimentContext;

// ---------------------------------------------------------
// Methods
// ---------------------------------------------------------

static void
generate_column_base_plaintext(small_aes_state_t plaintext, const size_t i) {
    // Random choice can produce collisions
    utils::get_random_bytes(plaintext, SMALL_AES_NUM_STATE_BYTES);

    // Non-random indexing the plaintext bytes that are not used to
    // create structures
    plaintext[2] = (uint8_t) ((i >> 24) & 0xFF);
    plaintext[3] = (uint8_t) ((i >> 16) & 0xFF);
    plaintext[4] = (uint8_t) ((i >> 8) & 0xFF);
    plaintext[5] = (uint8_t) (i & 0xFF);
}

// ---------------------------------------------------------

static void
get_column_text_from_delta_set(small_aes_state_t text, const size_t i) {
    // Extract from i = [i0 i1 i2 i3]
    // i0 x  x  x
    // i1 x  x  x
    // i2 x  x  x
    // i3 x  x  x
    text[0] = (uint8_t) ((i >> 8) & 0xFF);
    text[1] = (uint8_t) (i & 0xFF);
}

// ---------------------------------------------------------

static void encrypt(const small_aes_ctx_t *aes_context,
                    small_aes_state_t plaintext,
                    small_aes_state_t ciphertext,
                    const size_t num_rounds) {
    small_aes_encrypt_rounds_only_sbox_in_final(
        aes_context, plaintext, ciphertext, num_rounds
    );
}

// ---------------------------------------------------------

static size_t extract_column(const small_aes_state_t state,
                             const size_t column_index) {
    const size_t byte_index = 2 * column_index;
    return (state[byte_index] << 8) | state[byte_index + 1];
}

// ---------------------------------------------------------

static bool is_only_single_cell_active(const size_t column) {
    if (((column & 0xF000) != 0) && ((column & 0x0FFF) == 0)) {
        return true;
    }

    if (((column & 0x0F00) != 0) && ((column & 0xF0FF) == 0)) {
        return true;
    }

    if (((column & 0x00F0) != 0) && ((column & 0xFF0F) == 0)) {
        return true;
    }

    return ((column & 0x000F) != 0) && ((column & 0xFFF0) == 0);
}

// ---------------------------------------------------------

/**
 *
 * @param list
 * @param column_index Integer of 0,1,2,3
 * @param pair Plaintext-ciphertext pair
 */
static void insert_to_list(ColumnToPairsList &list,
                           size_t column_index,
                           const SmallStatePair &pair) {
    const size_t column_as_int = extract_column(pair.second, column_index);
    std::vector<SmallStatePair> &plaintexts_with_column = list[column_as_int];
    plaintexts_with_column.push_back(pair);
}

// ---------------------------------------------------------

static void insert_to_lists(ColumnToPairsList &list0,
                            ColumnToPairsList &list1,
                            ColumnToPairsList &list2,
                            ColumnToPairsList &list3,
                            const SmallStatePair &pair) {
    insert_to_list(list0, 0, pair);
    insert_to_list(list1, 1, pair);
    insert_to_list(list2, 2, pair);
    insert_to_list(list3, 3, pair);
}

// ---------------------------------------------------------

static void collect_pairs_for_structure(const small_aes_ctx_t *cipher_ctx,
                                        const size_t structure_index,
                                        const size_t num_rounds,
                                        ColumnToPairsList &list0,
                                        ColumnToPairsList &list1,
                                        ColumnToPairsList &list2,
                                        ColumnToPairsList &list3) {
    puts("# Collecting pairs");

    small_aes_state_t base_plaintext;
    generate_column_base_plaintext(base_plaintext, structure_index);

    for (size_t j = 0; j < NUM_TEXTS_PER_STRUCTURE; ++j) {
        // Prepare plaintext
        SmallStatePair pair;
        memcpy(pair.first, base_plaintext, SMALL_AES_NUM_STATE_BYTES);
        get_column_text_from_delta_set(pair.first, j);

        // Encrypt and store to four lists
        encrypt(cipher_ctx, pair.first, pair.second, num_rounds);
        insert_to_lists(list0, list1, list2, list3, pair);
    }

    puts("# Collecting pairs done");
}

// ---------------------------------------------------------

static void init_list(ColumnToPairsList &list, const size_t num_elements) {
    list.clear();
    list.resize(num_elements);
}

// ---------------------------------------------------------

static void init_lists(ColumnToPairsList &list0,
                       ColumnToPairsList &list1,
                       ColumnToPairsList &list2,
                       ColumnToPairsList &list3,
                       const size_t num_elements) {
    init_list(list0, num_elements);
    init_list(list1, num_elements);
    init_list(list2, num_elements);
    init_list(list3, num_elements);
}

// ---------------------------------------------------------

static bool collide_in_earlier_columns(const small_aes_state_t first_ciphertext,
                                       const small_aes_state_t second_ciphertext,
                                       const size_t list_index) {
    if (list_index > SMALL_AES_NUM_COLUMNS) {
        return false;
    }

    for (size_t i = 0; i < list_index; ++i) {
        const size_t first_column = extract_column(first_ciphertext, i);
        const size_t second_column = extract_column(second_ciphertext, i);

        if (first_column == second_column) {
            return true;
        }
    }

    return false;
}

// ---------------------------------------------------------

static IntegerPair count_collisions_in_list(const ColumnToPairsList &list,
                                            const size_t list_index) {
    small_aes_state_t delta_p;
    size_t num_delta_set_collisions = 0;
    size_t num_non_delta_set_collisions = 0;

    // For all column values
    for (auto const &texts_with_column_value: list) {
        // No collisions for the current column value
        if (texts_with_column_value.size() < 2) {
            continue;
        }

        // Collisions occurred
        for (size_t i = 0; i < texts_with_column_value.size(); ++i) {
            const SmallStatePair &first_text = texts_with_column_value[i];

            for (size_t j = i + 1; j < texts_with_column_value.size(); ++j) {
                const SmallStatePair &second_text = texts_with_column_value[j];

                // Look up if they collide in previous columns
                if (list_index > 0 &&
                    collide_in_earlier_columns(first_text.second,
                                               second_text.second,
                                               list_index)) {
                    continue;
                }

                xor_arrays(delta_p, first_text.first, second_text.first,
                           SMALL_AES_NUM_STATE_BYTES);
                const size_t p_column = extract_column(delta_p, 0);

                if (is_only_single_cell_active(p_column)) {
                    num_delta_set_collisions++;
                } else {
                    num_non_delta_set_collisions++;
                }
            }
        }
    }

    IntegerPair result(num_delta_set_collisions, num_non_delta_set_collisions);
    return result;
}

// ---------------------------------------------------------

static void count_collisions(ExperimentContext *context) {
    const IntegerPair result0 = count_collisions_in_list(context->list0, 0);
    const IntegerPair result1 = count_collisions_in_list(context->list1, 1);
    const IntegerPair result2 = count_collisions_in_list(context->list2, 2);
    const IntegerPair result3 = count_collisions_in_list(context->list3, 3);

    context->num_delta_set_collisions +=
        result0.first + result1.first + result2.first + result3.first;
    context->num_non_delta_set_collisions +=
        result0.second + result1.second + result2.second + result3.second;
}

// ---------------------------------------------------------

static double get_collision_probability(const size_t num_collisions,
                                        const size_t num_pairs) {
    return log2((double) num_collisions / num_pairs);
}

// ---------------------------------------------------------

static void print_collisions(const small_aes_key_t correct_key,
                             const size_t num_delta_set_collisions,
                             const size_t num_non_delta_set_collisions,
                             const size_t num_structures) {
    const size_t num_delta_set_pairs = 120 * 4 * (1L << 12) * num_structures;
    const size_t num_non_delta_set_pairs = num_structures *
                                           (NUM_TEXTS_PER_STRUCTURE *
                                            (NUM_TEXTS_PER_STRUCTURE - 1) / 2)
                                           - num_delta_set_pairs;

    const double delta_set_collision_probability = get_collision_probability(
        num_delta_set_collisions, num_delta_set_pairs);
    const double non_delta_set_collision_probability = get_collision_probability(
        num_non_delta_set_collisions, num_non_delta_set_pairs);

    print_hex("# Correct key: ", correct_key, SMALL_AES_NUM_STATE_BYTES);
    printf("# Collisions in delta sets:  %8zu\n", num_delta_set_collisions);
    printf("# Pr[coll] in delta sets:    %8.4f\n",
           delta_set_collision_probability);
    printf("# Collisions in other pairs: %8zu\n", num_non_delta_set_collisions);
    printf("# Pr[coll] in other pairs:   %8.4f\n",
           non_delta_set_collision_probability);
}

// ---------------------------------------------------------

static void perform_experiment(ExperimentContext *context) {
    // ---------------------------------------------------------
    // Set up the key
    // ---------------------------------------------------------

    small_aes_ctx_t *cipher_ctx = &context->cipher_ctx;
    small_aes_key_t correct_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
                                   0xef};

    utils::get_random_bytes(correct_key, SMALL_AES_NUM_KEY_BYTES);
    small_aes_key_setup(cipher_ctx, correct_key);

    context->num_delta_set_collisions = 0;
    context->num_non_delta_set_collisions = 0;

    // ---------------------------------------------------------
    // Encrypt texts
    // ---------------------------------------------------------

    for (size_t i = 0; i < context->num_structures_per_key; ++i) {
        printf("# Iteration %6zu\n", i);

        init_lists(context->list0, context->list1,
                   context->list2, context->list3, NUM_TEXTS_PER_STRUCTURE);
        collect_pairs_for_structure(cipher_ctx, i,
                                    NUM_CONSIDERED_ROUNDS,
                                    context->list0, context->list1,
                                    context->list2, context->list3);
        count_collisions(context);
    }

    puts("# Finished all structures\n");

    print_collisions(correct_key,
                     context->num_delta_set_collisions,
                     context->num_non_delta_set_collisions,
                     context->num_structures_per_key);
}

// ---------------------------------------------------------

static void perform_experiments(ExperimentContext *context) {
    for (size_t i = 0; i < context->num_keys; ++i) {
        perform_experiment(context);
    }
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static void
parse_args(ExperimentContext *context, int argc, const char **argv) {
    ArgumentParser parser;
    parser.appName("Test");
    parser.helpString("Evaluates with the Small-AES the number of inverse-"
                      "diagonal collisions after five rounds. The number is "
                      "evaluated for structures of plaintexts that iterate over "
                      "all values in the first column. We compare the number "
                      "for ciphertext pairs whose plaintexts are in a delta-set, "
                      "i.e., differ in only one byte, and such ciphertext pairs "
                      "whose plaintexts are not in a delta-set.");
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-s", "--num_structures_per_key", 1, false);

    try {
        parser.parse((size_t) argc, argv);

        context->num_keys = parser.retrieveAsLong("k");
        context->num_structures_per_key = parser.retrieveAsLong("s");
    } catch (...) {
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

    printf("# Keys      %8zu\n", context->num_keys);
    printf("# Sets/Key  %8zu\n", context->num_structures_per_key);
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(&context, argc, argv);
    perform_experiments(&context);
    return EXIT_SUCCESS;
}

