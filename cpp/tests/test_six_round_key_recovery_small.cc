/**
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */
#include <stdint.h>
#include <stdlib.h>

#include <map>
#include <vector>
#include <numeric>      // std::iota
#include <algorithm>    // std::sort

#include "ciphers/random_function.h"
#include "ciphers/small_aes.h"
#include "ciphers/small_state.h"
#include "ciphers/small_state_pair.h"
#include "ciphers/speck64.h"
#include "utils/argparse.h"
#include "utils/hash_table_generator.h"
#include "utils/utils.h"
#include "utils/xorshift1024.h"


using ciphers::SMALL_AES_SBOX_ARRAY;
using ciphers::small_aes_ctx_t;
using ciphers::small_aes_state_t;
using ciphers::small_aes_key_t;
using ciphers::SmallState;
using ciphers::SmallStatePair;
using ciphers::speck64_context_t;
using ciphers::speck64_96_key_t;
using ciphers::speck64_state_t;
using utils::ArgumentParser;
using utils::HashTableGenerator;
using utils::IntegerList;
using utils::IntegerMatrix;
using utils::print_hex;
using utils::to_uint64;
using utils::xor_arrays;
using utils::zeroize_array;

// ---------------------------------------------------------

const size_t NUM_TEXTS_PER_STRUCTURE = 1 << 16;

// ---------------------------------------------------------

typedef struct {
    small_aes_key_t key;
    small_aes_ctx_t cipher_ctx;
    size_t num_keys;
    size_t num_structures_per_key;
    IntegerList num_matches;
    size_t num_keys_to_print = 100;
    size_t num_considered_rounds = 6;
    std::vector<std::vector<IntegerMatrix> > hash_tables; // 4D
} ExperimentContext;

typedef std::vector<std::vector<SmallStatePair> > ColumnToPairsList;
typedef std::vector<SmallState> SmallStatesVector;

// ---------------------------------------------------------

static void
generate_diagonal_base_plaintext(small_aes_state_t plaintext, const size_t i) {
    // Zeroize
    // 0 x x x
    // x 0 x x
    // x x 0 x
    // x x x 0
    memset(plaintext, 0x00, SMALL_AES_NUM_STATE_BYTES);
    // Index the plaintext bytes that are not used for creating structures
    plaintext[1] = (uint8_t) ((i >> 24) & 0xFF);
    plaintext[3] = (uint8_t) ((i >> 16) & 0xFF);
    plaintext[4] = (uint8_t) ((i >> 8) & 0xFF);
    plaintext[6] = (uint8_t) (i & 0xFF);
}

// ---------------------------------------------------------

static void
generate_column_base_plaintext(small_aes_state_t plaintext, const size_t i) {
    // For K = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    const small_aes_state_t base_plaintext_after_one_round = {
        0x00, 0x00, 0x4f, 0x33, 0xd4, 0xfb, 0x33, 0x12
    };
    memcpy(plaintext,
           base_plaintext_after_one_round,
           SMALL_AES_NUM_STATE_BYTES);

    // Non-random indexing the plaintext bytes that are not used to
    // create structures
    plaintext[2] = (uint8_t) ((i >> 24) & 0xFF);
    plaintext[3] = (uint8_t) ((i >> 16) & 0xFF);
    plaintext[4] = (uint8_t) ((i >> 8) & 0xFF);
    plaintext[5] = (uint8_t) (i & 0xFF);
}

// ---------------------------------------------------------

static void
get_diagonal_text_from_delta_set(small_aes_state_t text, const size_t i) {
    // Extract from i = [i0 i1 i2 i3]
    // i0 x  x  x
    // x  i1 x  x
    // x  x  i2 x
    // x  x  x  i3
    text[0] = (uint8_t) ((i >> 8) & 0xF0);
    text[2] = (uint8_t) ((i >> 8) & 0x0F);
    text[5] = (uint8_t) (i & 0xF0);
    text[7] = (uint8_t) (i & 0x0F);
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

static size_t extract_diagonal(const small_aes_state_t state) {
    return (size_t) ((state[0] & 0xF0) << 8)
           | ((state[2] & 0x0F) << 8)
           | (state[5] & 0xF0)
           | (state[7] & 0x0F);
}

// ---------------------------------------------------------

static size_t to_diagonal(const IntegerList &list) {
    return ((list[0] & 0x0F) << 12)
           | ((list[1] & 0x0F) << 8)
           | ((list[2] & 0x0F) << 4)
           | (list[3] & 0x0F);
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

/**
 * https://stackoverflow.com/questions/1577475/c-sorting-and-keeping-track-of-indexes
 * @param sorted_key_indices
 * @param key_candidates
 */
static void sort_key_candidates(IntegerList &sorted_key_indices,
                                const IntegerList &key_candidates) {
    const size_t num_keys = key_candidates.size();
    sorted_key_indices.resize(num_keys);

    // Initialize original index locations
    std::iota(sorted_key_indices.begin(), sorted_key_indices.end(), 0);

    // Sort indexes based on comparing values in key_candidates
    std::sort(
        sorted_key_indices.begin(),
        sorted_key_indices.end(),
        [&key_candidates](const size_t left_index, const size_t right_index) {
            // Sort in descending order
            return key_candidates[left_index] > key_candidates[right_index];
        }
    );
}

// ---------------------------------------------------------

static void print_best_key_candidates(const small_aes_key_t correct_key,
                                      const IntegerList &sorted_key_indices,
                                      const IntegerList &key_candidates,
                                      const size_t num_to_print) {
    const size_t correct_key_part = extract_diagonal(correct_key);
    const size_t correct_key_count = key_candidates[correct_key_part];
    printf("Correct key: %04zx %8zu\n", correct_key_part, correct_key_count);

    for (size_t i = 0; i < num_to_print; ++i) {
        const size_t key_candidate = sorted_key_indices[i];
        const size_t count = key_candidates[key_candidate];
        printf("%4zu: %04zx %8zu\n", i + 1, key_candidate, count);
    }
}

// ---------------------------------------------------------

static void increment_counters(const ExperimentContext *context,
                               IntegerList &key_candidates,
                               const size_t p_diagonal,
                               const size_t delta_p_diagonal) {
    for (size_t k = 0; k < SMALL_AES_NUM_COLUMNS; ++k) {
        // Get hash table for row
        const std::vector<IntegerMatrix> &hash_table = context->hash_tables[k];

        // Get the key candidates that can produce this collision
        const std::vector<IntegerList> &transitions =
            hash_table[delta_p_diagonal];

        if (transitions.empty()) {
            continue;
        }

        for (const IntegerList &diagonals_after_add_key : transitions) {
            // Example:
            // - column = K xor P = [{0, 2, e, c}, {0, 2, e, d}]
            // - P = {3, 4, 5, 6}
            // Then, the key candidates are
            // K = column xor P = [{3, 6, b, a}, {3, 6, b, b}].

            const size_t diagonal_after_add_key = to_diagonal(
                diagonals_after_add_key);
            const size_t key_diagonal = p_diagonal ^diagonal_after_add_key;
            key_candidates[key_diagonal]++;
        }
    }
}

// ---------------------------------------------------------

static void find_collisions(const ExperimentContext *context,
                            const ColumnToPairsList &target_list,
                            IntegerList &key_candidates,
                            const size_t list_index) {
    // For all column values
    for (auto const &texts_with_column_value: target_list) {
        // No collisions for the current column value
        if (texts_with_column_value.size() < 2) {
            continue;
        }

        // Collisions occurred
        for (size_t i = 0; i < texts_with_column_value.size(); ++i) {
            const SmallStatePair &first_text = texts_with_column_value[i];
            const size_t p_diagonal = extract_diagonal(first_text.first);

            for (size_t j = i + 1; j < texts_with_column_value.size(); ++j) {
                const SmallStatePair &second_text = texts_with_column_value[j];

                // Look up if they collide in previous columns
                if (list_index > 0 &&
                    collide_in_earlier_columns(first_text.second,
                                               second_text.second,
                                               list_index)) {
                    continue;
                }

                small_aes_state_t delta_p;
                xor_arrays(delta_p,
                           first_text.first,
                           second_text.first,
                           SMALL_AES_NUM_STATE_BYTES);
                const size_t delta_p_diagonal = extract_diagonal(delta_p);

                increment_counters(
                    context, key_candidates, p_diagonal, delta_p_diagonal
                );
            }
        }
    }
}

// ---------------------------------------------------------

static void count_keys(const ExperimentContext *context,
                       ColumnToPairsList &list0,
                       ColumnToPairsList &list1,
                       ColumnToPairsList &list2,
                       ColumnToPairsList &list3,
                       IntegerList &key_candidates) {
    // puts("# Counting keys");

    find_collisions(context, list0, key_candidates, 0);
    find_collisions(context, list1, key_candidates, 1);
    find_collisions(context, list2, key_candidates, 2);
    find_collisions(context, list3, key_candidates, 3);

    // puts("# Counting keys done");
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
    // puts("# Collecting pairs");

    small_aes_state_t base_plaintext;
    generate_diagonal_base_plaintext(base_plaintext, structure_index);

    for (size_t j = 0; j < NUM_TEXTS_PER_STRUCTURE; ++j) {
        // Prepare plaintext
        SmallStatePair pair;
        memcpy(pair.first, base_plaintext, SMALL_AES_NUM_STATE_BYTES);
        get_diagonal_text_from_delta_set(pair.first, j);

        // Encrypt and store to four lists
        encrypt(cipher_ctx, pair.first, pair.second, num_rounds);
        insert_to_lists(list0, list1, list2, list3, pair);
    }

    // puts("# Collecting pairs done");
}

// ---------------------------------------------------------

static void precompute_hash_tables(ExperimentContext *context) {
    puts("# Precomputing hash tables");

    std::vector<std::vector<IntegerList> > extended_ddt;
    HashTableGenerator generator;

    generator.compute_extended_ddt(extended_ddt, SMALL_AES_SBOX_ARRAY, 16);

    for (size_t i = 0; i < SMALL_AES_NUM_ROWS; ++i) {
        std::vector<IntegerMatrix> hash_table;
        generator.create_hash_table(hash_table, i, extended_ddt);
        context->hash_tables.push_back(hash_table);
    }

    puts("# Precomputing hash tables done");
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

static void perform_experiment(ExperimentContext *context) {
    // ---------------------------------------------------------
    // Set up the key
    // ---------------------------------------------------------

    small_aes_ctx_t *cipher_ctx = &context->cipher_ctx;
    small_aes_key_t correct_key;

    utils::get_random_bytes(correct_key, SMALL_AES_NUM_KEY_BYTES);
    print_hex("# Full correct key", correct_key, SMALL_AES_NUM_KEY_BYTES);
    small_aes_key_setup(cipher_ctx, correct_key);

    IntegerList key_candidates;
    key_candidates.resize(NUM_TEXTS_PER_STRUCTURE, 0);

    // ---------------------------------------------------------
    // Set up the lists to store the pairs for the ciphertext columns
    // ---------------------------------------------------------

    ColumnToPairsList list0;
    ColumnToPairsList list1;
    ColumnToPairsList list2;
    ColumnToPairsList list3;

    // ---------------------------------------------------------
    // Encrypt texts
    // ---------------------------------------------------------

    IntegerList sorted_key_indices;

    for (size_t i = 0; i < context->num_structures_per_key; ++i) {
        printf("# Iteration %6zu\n", i);

        init_lists(list0, list1, list2, list3, NUM_TEXTS_PER_STRUCTURE);
        collect_pairs_for_structure(cipher_ctx, i,
                                    context->num_considered_rounds, list0,
                                    list1, list2, list3);
        count_keys(context, list0, list1, list2, list3, key_candidates);

        if (i > 0 && (i % 100 == 0)) {
            sort_key_candidates(sorted_key_indices, key_candidates);
            print_best_key_candidates(correct_key,
                                      sorted_key_indices,
                                      key_candidates,
                                      context->num_keys_to_print);
        }
    }

    puts("# Finished all structures\n");

    sort_key_candidates(sorted_key_indices, key_candidates);
    print_best_key_candidates(correct_key, sorted_key_indices, key_candidates,
                              NUM_TEXTS_PER_STRUCTURE);
}

// ---------------------------------------------------------
// Helper methods for the test that evaluates the would-be counts for the
// correct key for one structure.
// ---------------------------------------------------------

static bool is_only_single_cell_active(const size_t columns) {
    if (((columns & 0xF000) != 0) && ((columns & 0x0FFF) == 0)) {
        return true;
    }

    if (((columns & 0x0F00) != 0) && ((columns & 0xF0FF) == 0)) {
        return true;
    }

    if (((columns & 0x00F0) != 0) && ((columns & 0xFF0F) == 0)) {
        return true;
    }

    return ((columns & 0x000F) != 0) && ((columns & 0xFFF0) == 0);
}

// ---------------------------------------------------------

static size_t
count_num_collisions_for_list(const ColumnToPairsList &target_list,
                              const size_t list_index) {
    printf("# Searching collisions in column %2zu\n", list_index);

    size_t num_collisions = 0;
    const size_t column_index = 0;

    // For all column values
    for (auto const &texts_with_column_value: target_list) {
        // No collisions for the current column value
        if (texts_with_column_value.size() < 2) {
            continue;
        }

        // Collisions occurred
        for (size_t i = 0; i < texts_with_column_value.size(); ++i) {
            const SmallStatePair &first_text = texts_with_column_value[i];
            const size_t first_column = extract_column(first_text.first,
                                                       column_index);

            for (size_t j = i + 1; j < texts_with_column_value.size(); ++j) {
                const SmallStatePair &second_text = texts_with_column_value[j];
                const size_t second_column = extract_column(second_text.first,
                                                            column_index);
                const size_t delta_p = first_column ^second_column;

                // Check if it is a plaintext pair from a delta-set
                if (!is_only_single_cell_active(delta_p)) {
                    continue;
                }

                // Look up if they collide in previous columns
                if (list_index > 0 &&
                    collide_in_earlier_columns(first_text.second,
                                               second_text.second,
                                               list_index)) {
                    continue;
                }

                num_collisions++;
            }
        }
    }

    printf("# Found %8zu collisions in column %2zu done\n", num_collisions,
           list_index);
    return num_collisions;
}

// ---------------------------------------------------------

static size_t
count_num_collisions_for_all_lists(ColumnToPairsList &list0,
                                   ColumnToPairsList &list1,
                                   ColumnToPairsList &list2,
                                   ColumnToPairsList &list3) {
    puts("# Counting keys");

    size_t num_total_collisions = 0;
    num_total_collisions += count_num_collisions_for_list(list0, 0);
    num_total_collisions += count_num_collisions_for_list(list1, 1);
    num_total_collisions += count_num_collisions_for_list(list2, 2);
    num_total_collisions += count_num_collisions_for_list(list3, 3);

    puts("# Counting keys done");

    return num_total_collisions;
}

// ---------------------------------------------------------

static void
collect_column_pairs_for_structure(const small_aes_ctx_t *cipher_ctx,
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

static void move_subkeys_one_round_forwards(small_aes_ctx_t *cipher_ctx,
                                            const size_t num_considered_rounds) {
    for (size_t i = 0; i < num_considered_rounds; ++i) {
        cipher_ctx->key[i] = cipher_ctx->key[i + 1];
    }
}

// ---------------------------------------------------------

/**
 * Encrypts the would-be plaintexts for the default key and determine the
 * number of collisions through r - 1 rounds.
 */
static void perform_counting_test(ExperimentContext *context) {
    // ---------------------------------------------------------
    // Set up the key
    // ---------------------------------------------------------

    small_aes_ctx_t *cipher_ctx = &context->cipher_ctx;
    small_aes_key_t correct_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
                                   0xef};

    small_aes_key_setup(cipher_ctx, correct_key);
    move_subkeys_one_round_forwards(cipher_ctx, context->num_considered_rounds);

    // ---------------------------------------------------------
    // Set up the lists to store the pairs for the ciphertext columns
    // ---------------------------------------------------------

    ColumnToPairsList list0;
    ColumnToPairsList list1;
    ColumnToPairsList list2;
    ColumnToPairsList list3;

    // ---------------------------------------------------------
    // Encrypt texts
    // ---------------------------------------------------------

    const size_t structure_index = 0;
    const size_t num_rounds = context->num_considered_rounds - 1;

    init_lists(list0, list1, list2, list3, NUM_TEXTS_PER_STRUCTURE);
    collect_column_pairs_for_structure(cipher_ctx, structure_index, num_rounds,
                                       list0, list1, list2, list3);
    const size_t num_collisions = count_num_collisions_for_all_lists(
        list0, list1, list2, list3
    );
    printf("# Collisions:    %8zu\n", num_collisions);
}

// ---------------------------------------------------------

static void perform_experiments(ExperimentContext *context) {
    for (size_t i = 0; i < context->num_keys; ++i) {
        (void) perform_counting_test; // Unused, but prevent compiler warning
        perform_experiment(context);
    }
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static void
parse_args(ExperimentContext *context, int argc, const char **argv) {
    ArgumentParser parser;
    parser.appName("Test for the Small-AES six-round key recovery.");
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
    precompute_hash_tables(&context);
    perform_experiments(&context);
    return EXIT_SUCCESS;
}
