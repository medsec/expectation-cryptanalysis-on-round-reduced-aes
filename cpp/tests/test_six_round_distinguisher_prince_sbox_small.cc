/**
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <array>
#include <map>
#include <chrono>
#include <vector>
#include <numeric>      // std::iota
#include <algorithm>    // std::sort

#include "ciphers/random_function.h"
#include "ciphers/small_aes.h"
#include "ciphers/small_aes_prince_sbox.h"
#include "ciphers/small_state.h"
#include "ciphers/small_state_pair.h"
#include "ciphers/speck64.h"
#include "utils/argparse.h"
#include "utils/hash_table_generator.h"
#include "utils/utils.h"
#include "utils/xorshift1024.h"


using ciphers::small_aes_ctx_t;
using ciphers::small_aes_state_t;
using ciphers::small_aes_key_t;
using ciphers::SmallState;
using ciphers::speck64_context_t;
using ciphers::speck64_96_key_t;
using ciphers::speck64_state_t;
using utils::ArgumentParser;
using utils::print_hex;
using utils::to_uint64;
using utils::convert_to_uint64;
using utils::zeroize_array;

// ---------------------------------------------------------
// Constants
// ---------------------------------------------------------

const size_t NUM_TEXTS_PER_STRUCTURE = 1 << 16;
const size_t NUM_CONSIDERED_ROUNDS = 6;

// ---------------------------------------------------------
// Types
// ---------------------------------------------------------

typedef std::pair<size_t, size_t> IntegerPair;
typedef std::array<uint64_t, NUM_TEXTS_PER_STRUCTURE> UInt64List;
typedef std::vector<uint64_t> UInt64Vector;

typedef struct {
    small_aes_key_t key;
    small_aes_ctx_t cipher_ctx;
    bool has_set_key = false;
    size_t num_collisions = 0;
    size_t num_multi_column_collisions = 0;
    size_t num_keys = 0;
    size_t num_structures_per_key = 0;
    size_t structure_start_index = 0;
    UInt64List list;
    UInt64List count_lists[SMALL_AES_NUM_COLUMNS];
} ExperimentContext;

// ----------------------------------------------------------
// Logging functions
// ----------------------------------------------------------

static void log(const std::string &label,
                         const size_t value) {
    std::cout << label << std::setw(8) << value << '\n';
}

// ---------------------------------------------------------

static void log(const std::string &label,
                       const double value) {
    std::cout << label << std::setw(8) << std::setprecision(4) << value << '\n';
}

// ---------------------------------------------------------
// Helper methods
// ---------------------------------------------------------

static __m128i
generate_diagonal_base_plaintext(const size_t i) {
    // Zeroize
    // 0 x x x
    // x 0 x x
    // x x 0 x
    // x x x 0
    return vsetr8(
        0, 0, (uint8_t) ((i >> 28) & 0xF), (uint8_t) ((i >> 24) & 0xF),
        0, 0, (uint8_t) ((i >> 20) & 0xF), (uint8_t) ((i >> 16) & 0xF),
        (uint8_t) ((i >> 12) & 0xF), (uint8_t) ((i >> 8) & 0xF), 0, 0,
        (uint8_t) ((i >> 4) & 0xF), (uint8_t) (i & 0xF), 0, 0
    );
}

// ---------------------------------------------------------

static __m128i
get_diagonal_text_from_delta_set(const __m128i base_plaintext, const size_t i) {
    // Extract from i = [i0 i1 i2 i3]
    // i0 x  x  x
    // x  i1 x  x
    // x  x  i2 x
    // x  x  x  i3

    return vxor(base_plaintext, vsetr8(
        (uint8_t) ((i >> 12) & 0xF), 0, 0, 0,
        0, (uint8_t) ((i >> 8) & 0xF), 0, 0,
        0, 0, (uint8_t) ((i >> 4) & 0xF), 0,
        0, 0, 0, (uint8_t) (i & 0xF)
    ));
}

// ---------------------------------------------------------

static inline __m128i encrypt(const small_aes_ctx_t *aes_context,
                              __m128i plaintext,
                              const size_t num_rounds) {
    return small_aes_prince_sbox_encrypt_rounds_only_sbox_in_final_with_aes_ni(
        aes_context, plaintext, num_rounds
    );
}

// ---------------------------------------------------------

static inline size_t extract_column_from_int(const uint64_t state,
                                             const size_t column_index) {
    const size_t shift = (3 - column_index) * 16;
    return (state >> shift) & 0xFFFF;
}

// ---------------------------------------------------------

static bool collide_in_column(const uint64_t first,
                              const uint64_t second,
                              const size_t column_index) {
    const uint64_t difference = first ^second;
    const uint64_t mask = 0xFFFF000000000000 >> (column_index * 16);
    return (difference & mask) == 0;
}

// ---------------------------------------------------------

static bool collide_in_later_columns(const uint64_t first,
                                     const uint64_t second,
                                     const size_t column_index) {
    if (column_index == 3) {
        return false;
    }

    const uint64_t difference = first ^second;

    if ((difference & 0x0000FFFF00000000) == 0) {
        return true;
    }

    if (column_index == 2) {
        return false;
    }

    if ((difference & 0x00000000FFFF0000) == 0) {
        return true;
    }

    if (column_index == 1) {
        return false;
    }

    return (difference & 0x000000000000FFFF) == 0;
}

// ---------------------------------------------------------

static void shift_values_in_list(UInt64List &list) {
    for (size_t i = 0; i < NUM_TEXTS_PER_STRUCTURE; ++i) {
        list[i] <<= 16;
    }
}

// ---------------------------------------------------------

static void sort_list(UInt64Vector &sorted_list,
                      const UInt64List &original_list,
                      const UInt64List &count_list) {
    const size_t num_texts = original_list.size();
    sorted_list.clear();

    for (size_t i = 0; i < num_texts; ++i) {
        const uint64_t text = original_list[i];
        // Use column 0 since we shift!
        const size_t column_value = extract_column_from_int(text, 0);

        if (count_list[column_value] <= 1) {
            continue;
        }

        sorted_list.push_back(text);
    }

    std::sort(sorted_list.begin(), sorted_list.end());
}

// ---------------------------------------------------------

static IntegerPair count_collisions_in_list(const UInt64List &list,
                                            const UInt64List &count_list,
                                            const size_t column_index) {
    size_t num_collisions = 0;
    size_t num_multi_column_collisions = 0;
    UInt64Vector sorted_list;

    sort_list(sorted_list, list, count_list);
    size_t num_texts = sorted_list.size();

    // Find collisions
    for (size_t i = 0; i < num_texts; ++i) {
        const uint64_t first = sorted_list[i];

        for (size_t j = i + 1; j < num_texts; ++j) {
            const uint64_t second = sorted_list[j];

            // Collide in first column since we shift
            if (!collide_in_column(first, second, 0)) {
                break;
            }

            if (collide_in_later_columns(first, second, column_index)) {
                num_multi_column_collisions++;
                continue;
            }

            num_collisions++;
        }
    }

    IntegerPair result(num_collisions, num_multi_column_collisions);
    return result;
}

// ---------------------------------------------------------

static IntegerPair count_collisions(ExperimentContext *context) {
    IntegerPair result(0, 0);

    for (size_t column_index = 0;
         column_index < SMALL_AES_NUM_COLUMNS;
         ++column_index) {

        const IntegerPair pair = count_collisions_in_list(
            context->list, context->count_lists[column_index], column_index
        );
        result.first += pair.first;
        result.second += pair.second;
        shift_values_in_list(context->list);
    }

    return result;
}

// ---------------------------------------------------------

static void collect_pairs_for_structure(const small_aes_ctx_t *cipher_ctx,
                                        const size_t structure_index,
                                        const size_t num_rounds,
                                        UInt64List &list,
                                        UInt64List count_lists[SMALL_AES_NUM_COLUMNS]) {
    __m128i base_plaintext = generate_diagonal_base_plaintext(structure_index);

    for (size_t j = 0; j < NUM_TEXTS_PER_STRUCTURE; ++j) {
        // Prepare plaintext
        const __m128i plaintext = get_diagonal_text_from_delta_set(
            base_plaintext, j);

        // Encrypt and store to four lists
        const __m128i ciphertext = encrypt(cipher_ctx, plaintext, num_rounds);
        const uint64_t ciphertext_as_int = convert_to_uint64(ciphertext);
        list[j] = ciphertext_as_int;

        for (size_t i = 0; i < SMALL_AES_NUM_COLUMNS; ++i) {
            const size_t column_value = extract_column_from_int(
                ciphertext_as_int, i);
            count_lists[i][column_value]++;
        }
    }
}

// ---------------------------------------------------------

static void print_collisions(const size_t num_collisions,
                             const size_t num_multi_column_collisions,
                             const size_t num_structures) {
    log("# Collisions:  ", num_collisions);
    log("# Multi-Colls: ", num_multi_column_collisions);
    log("# Structures:  ", num_structures);
}

// ---------------------------------------------------------

static void init_lists(UInt64List lists[SMALL_AES_NUM_COLUMNS],
                       const size_t num_elements) {
    for (size_t i = 0; i < SMALL_AES_NUM_COLUMNS; ++i) {
        for (size_t j = 0; j < num_elements; ++j) {
            lists[i][j] = 0;
        }
    }
}

// ---------------------------------------------------------
// Experiment
// ---------------------------------------------------------

static void perform_experiment(ExperimentContext *context) {
    // ---------------------------------------------------------
    // Set up the key
    // ---------------------------------------------------------

    small_aes_ctx_t *cipher_ctx = &context->cipher_ctx;

    if (!context->has_set_key) {
        utils::get_random_bytes(context->key, SMALL_AES_NUM_KEY_BYTES);
    }

    small_aes_key_setup(cipher_ctx, context->key);
    context->num_collisions = 0;
    context->num_multi_column_collisions = 0;

    // ---------------------------------------------------------
    // Encrypt texts
    // ---------------------------------------------------------

    print_hex("# Key value", context->key, SMALL_AES_NUM_STATE_BYTES);
    std::cout << "# Iteration Collisions" << '\n';

    // ---------------------------------------------------------

    for (size_t i = context->structure_start_index;
         i < context->num_structures_per_key;
         ++i) {

        init_lists(context->count_lists, NUM_TEXTS_PER_STRUCTURE);
        collect_pairs_for_structure(cipher_ctx, i, NUM_CONSIDERED_ROUNDS,
                                    context->list, context->count_lists);
        const IntegerPair pair = count_collisions(context);
        context->num_collisions += pair.first;
        context->num_multi_column_collisions += pair.second;

        std::cout << std::setw(8) << pair.first
                  << " "
                  << std::setw(8) << pair.second
                  << '\n';
    }

    // ---------------------------------------------------------

    std::cout << "# Finished all structures" << '\n';

    print_collisions(context->num_collisions,
                     context->num_multi_column_collisions,
                     context->num_structures_per_key);
}

// ---------------------------------------------------------

static void perform_experiments(ExperimentContext *context) {
    for (size_t i = 0; i < context->num_keys; ++i) {
        perform_experiment(context);
    }
}

// ---------------------------------------------------------

static void print_time(const double num_elapsed_seconds,
                       const size_t num_structures) {
    log("# Seconds:     ", num_elapsed_seconds);
    log("# Sec./Struct: ", num_elapsed_seconds / num_structures);
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static void
parse_args(ExperimentContext *context, int argc, const char **argv) {
    ArgumentParser parser;
    parser.appName("Test for the Small-AES six-round distinguisher.");
    parser.helpString("Evaluates with the Small-AES the number of inverse-"
                      "diagonal collisions after six rounds. The number is "
                      "evaluated for structures of plaintexts that iterate over "
                      "all values in the first diagonal.");
    parser.useExceptions(true);
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-s", "--num_structures_per_key", 1, false);
    parser.addArgument("-j", "--key_value", 1, true);
    parser.addArgument("-i", "--structure_index", 1, true);

    try {
        parser.parse((size_t) argc, argv);
        zeroize_array(context->key, SMALL_AES_NUM_STATE_BYTES);

        context->num_keys = parser.retrieveAsLong("k");
        context->num_structures_per_key = parser.retrieveAsLong("s");

        if (parser.wasSet("-i")) {
            context->structure_start_index = parser.retrieveAsLong("i");
        }

        if (parser.wasSet("-j")) {
            context->has_set_key = true;
            parser.retrieveUint8ArrayFromHexString("j", context->key,
                                                   SMALL_AES_NUM_STATE_BYTES);
        }
    } catch (...) {
        std::cerr << parser.usage().c_str() << std::endl;
        exit(EXIT_FAILURE);
    }

    log("# Keys            ", context->num_keys);
    log("# Sets/Key        ", context->num_structures_per_key);
    log("# Start structure ", context->structure_start_index);
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(&context, argc, argv);

    const auto start = std::chrono::system_clock::now();
    perform_experiments(&context);

    const auto end = std::chrono::system_clock::now();
    const std::chrono::duration<double> elapsed_seconds = end - start;
    print_time(elapsed_seconds.count(), context.num_structures_per_key);

    return EXIT_SUCCESS;
}
