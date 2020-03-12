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
#include "ciphers/aes_tables.h"
#include "ciphers/small_aes.h"
#include "ciphers/small_aes_present_sbox.h"
#include "ciphers/small_aes_pride_sbox.h"
#include "ciphers/small_aes_prince_sbox.h"
#include "ciphers/small_aes_toy6_sbox.h"
#include "ciphers/small_aes_toy8_sbox.h"
#include "ciphers/small_aes_toy10_sbox.h"
#include "ciphers/small_aes_random_sbox.h"
#include "ciphers/small_sboxes.h"
#include "ciphers/small_state.h"
#include "ciphers/speck64.h"
#include "utils/argparse.h"
#include "utils/utils.h"
#include "utils/uint128_t.h"
#include "utils/xorshift1024.h"

using utils::ArgumentParser;

// ---------------------------------------------------------

typedef std::vector<size_t> Array;
typedef std::vector<Array> Array2D;
typedef std::vector<Array2D> Array3D;

typedef struct {
    Array x2;
    Array x3;
    Array _1SBOX;
    Array _2SBOX;
    Array _3SBOX;
    size_t num_values;
    size_t num_positions;
    size_t input_start_index;
    size_t output_start_index;
    Array2D a;
    Array2D b;
    Array2D c;
    Array2D d;
} ExperimentContext;

static const size_t NUM_4_BIT_SBOXES = 54;
static const size_t NUM_8_BIT_SBOXES = 1;

// ---------------------------------------------------------
// Functions
// ---------------------------------------------------------

#ifdef DEBUG
static void print_vector(const Array &table) {
    for (size_t i = 0; i < table.size(); ++i) {
        printf("%02lu ", table[i]);
    }

    puts("");
}

// ---------------------------------------------------------

static void print_vector(const Array2D &table) {
    for (size_t i = 0; i < table.size(); ++i) {
        print_vector(table[i]);
    }
}

// ---------------------------------------------------------

static void print_vector(const Array3D &table) {
    for (size_t i = 0; i < table.size(); ++i) {
        print_vector(table[i]);
    }
}

// ---------------------------------------------------------

static void print_vector_hex(const Array &table) {
    for (size_t i = 0; i < table.size(); ++i) {
        printf("%02lx ", table[i]);
    }

    puts("");
}

// ---------------------------------------------------------

static void print_vector_hex(const Array2D &table) {
    for (size_t i = 0; i < table.size(); ++i) {
        print_vector_hex(table[i]);
    }
}

// ---------------------------------------------------------

static void print_vector_hex(const Array3D &table) {
    for (size_t i = 0; i < table.size(); ++i) {
        print_vector_hex(table[i]);
    }
}
#endif

// ---------------------------------------------------------

static void zeroize_array(Array &table) {
    for (size_t i = 0; i < table.size(); ++i) {
        table[i] = 0;
    }
}

// ---------------------------------------------------------

static void zeroize_2d_array(Array2D &table) {
    for (size_t i = 0; i < table.size(); ++i) {
        zeroize_array(table[i]);
    }
}

// ---------------------------------------------------------

static void zeroize_3d_array(Array3D &table) {
    for (size_t i = 0; i < table.size(); ++i) {
        zeroize_2d_array(table[i]);
    }
}

// ---------------------------------------------------------

static void compute_input_variables0(ExperimentContext &context,
                                     const size_t num_values) {
    for (size_t k1 = 0; k1 < num_values; ++k1) {
        for (size_t x = 0; x < num_values; ++x) {
            context.a[k1][x] = context._1SBOX[context.x2[x] ^ k1];
            context.b[k1][x] = context._1SBOX[x ^ k1];
            context.c[k1][x] = context._1SBOX[x ^ k1];
            context.d[k1][x] = context._1SBOX[context.x3[x] ^ k1];
        }
    }
}

// ---------------------------------------------------------

static void compute_input_variables1(ExperimentContext &context,
                                     const size_t num_values) {
    for (size_t k1 = 0; k1 < num_values; ++k1) {
        for (size_t x = 0; x < num_values; ++x) {
            context.a[k1][x] = context._1SBOX[context.x3[x] ^ k1];
            context.b[k1][x] = context._1SBOX[context.x2[x] ^ k1];
            context.c[k1][x] = context._1SBOX[x ^ k1];
            context.d[k1][x] = context._1SBOX[x ^ k1];
        }
    }
}

// ---------------------------------------------------------

static void compute_input_variables2(ExperimentContext &context,
                                     const size_t num_values) {
    for (size_t k1 = 0; k1 < num_values; ++k1) {
        for (size_t x = 0; x < num_values; ++x) {
            context.a[k1][x] = context._1SBOX[x ^ k1];
            context.b[k1][x] = context._1SBOX[context.x3[x] ^ k1];
            context.c[k1][x] = context._1SBOX[context.x2[x] ^ k1];
            context.d[k1][x] = context._1SBOX[x ^ k1];
        }
    }
}

// ---------------------------------------------------------

static void compute_input_variables3(ExperimentContext &context,
                                     const size_t num_values) {
    for (size_t k1 = 0; k1 < num_values; ++k1) {
        for (size_t x = 0; x < num_values; ++x) {
            context.a[k1][x] = context._1SBOX[x ^ k1];
            context.b[k1][x] = context._1SBOX[x ^ k1];
            context.c[k1][x] = context._1SBOX[context.x3[x] ^ k1];
            context.d[k1][x] = context._1SBOX[context.x2[x] ^ k1];
        }
    }
}

// ---------------------------------------------------------

static void
compute_input_variables(ExperimentContext &context,
                        const size_t input_row_index) {
    if (input_row_index == 0) {
        compute_input_variables0(context, context.num_values);
    } else if (input_row_index == 1) {
        compute_input_variables1(context, context.num_values);
    } else if (input_row_index == 2) {
        compute_input_variables2(context, context.num_values);
    } else if (input_row_index == 3) {
        compute_input_variables3(context, context.num_values);
    }
}

// ---------------------------------------------------------

static void compute_output_variables0(ExperimentContext &context,
                                      Array3D &tables,
                                      const size_t output_row_index,
                                      const size_t num_values) {
    Array a_sbox = context._2SBOX;
    Array b_sbox = context._1SBOX;
    Array c_sbox = context._1SBOX;
    Array d_sbox = context._3SBOX;

    if (output_row_index == 1) {
        a_sbox = context._1SBOX;
        b_sbox = context._1SBOX;
        c_sbox = context._3SBOX;
        d_sbox = context._2SBOX;
    } else if (output_row_index == 2) {
        a_sbox = context._1SBOX;
        b_sbox = context._3SBOX;
        c_sbox = context._2SBOX;
        d_sbox = context._1SBOX;
    } else if (output_row_index == 3) {
        a_sbox = context._3SBOX;
        b_sbox = context._2SBOX;
        c_sbox = context._1SBOX;
        d_sbox = context._1SBOX;
    }

    for (size_t k1 = 0; k1 < num_values; ++k1) {
        for (size_t x = 0; x < num_values; ++x) {
            const size_t a = context.a[k1][x];
            const size_t b = context.b[k1][x];
            const size_t c = context.c[k1][x];
            const size_t d = context.d[k1][x];

            for (size_t k2 = 0; k2 < num_values; ++k2) {
                const size_t key_index = (k2 * num_values) + k1;

                tables[0][key_index][x] = a_sbox[context.x2[a] ^ k2];
                tables[1][key_index][x] = b_sbox[b ^ k2];
                tables[2][key_index][x] = c_sbox[context.x2[c] ^ k2];
                tables[3][key_index][x] = d_sbox[d ^ k2];
            }
        }
    }
}

// ---------------------------------------------------------

static void compute_output_variables1(ExperimentContext &context,
                                      Array3D &tables,
                                      const size_t output_row_index,
                                      const size_t num_values) {
    Array a_sbox = context._3SBOX;
    Array b_sbox = context._2SBOX;
    Array c_sbox = context._1SBOX;
    Array d_sbox = context._1SBOX;

    if (output_row_index == 1) {
        a_sbox = context._2SBOX;
        b_sbox = context._1SBOX;
        c_sbox = context._1SBOX;
        d_sbox = context._3SBOX;
    } else if (output_row_index == 2) {
        a_sbox = context._1SBOX;
        b_sbox = context._1SBOX;
        c_sbox = context._3SBOX;
        d_sbox = context._2SBOX;
    } else if (output_row_index == 3) {
        a_sbox = context._1SBOX;
        b_sbox = context._3SBOX;
        c_sbox = context._2SBOX;
        d_sbox = context._1SBOX;
    }

    for (size_t k1 = 0; k1 < num_values; ++k1) {
        for (size_t k2 = 0; k2 < num_values; ++k2) {
            for (size_t x = 0; x < num_values; ++x) {
                const size_t a = context.a[k1][x];
                const size_t b = context.b[k1][x];
                const size_t c = context.c[k1][x];
                const size_t d = context.d[k1][x];
                const size_t key_index = (k2 * num_values) + k1;

                tables[0][key_index][x] = a_sbox[a ^ k2];
                tables[1][key_index][x] = b_sbox[context.x3[b] ^ k2];
                tables[2][key_index][x] = c_sbox[c ^ k2];
                tables[3][key_index][x] = d_sbox[context.x3[d] ^ k2];
            }
        }
    }
}

// ---------------------------------------------------------

static void compute_output_variables2(ExperimentContext &context,
                                      Array3D &tables,
                                      const size_t output_row_index,
                                      const size_t num_values) {
    Array a_sbox = context._1SBOX;
    Array b_sbox = context._3SBOX;
    Array c_sbox = context._2SBOX;
    Array d_sbox = context._1SBOX;

    if (output_row_index == 1) {
        a_sbox = context._3SBOX;
        b_sbox = context._2SBOX;
        c_sbox = context._1SBOX;
        d_sbox = context._1SBOX;
    } else if (output_row_index == 2) {
        a_sbox = context._2SBOX;
        b_sbox = context._1SBOX;
        c_sbox = context._1SBOX;
        d_sbox = context._3SBOX;
    } else if (output_row_index == 3) {
        a_sbox = context._1SBOX;
        b_sbox = context._1SBOX;
        c_sbox = context._3SBOX;
        d_sbox = context._2SBOX;
    }

    for (size_t k1 = 0; k1 < num_values; ++k1) {
        for (size_t k2 = 0; k2 < num_values; ++k2) {
            for (size_t x = 0; x < num_values; ++x) {
                const size_t a = context.a[k1][x];
                const size_t b = context.b[k1][x];
                const size_t c = context.c[k1][x];
                const size_t d = context.d[k1][x];
                const size_t key_index = (k2 * num_values) + k1;

                tables[0][key_index][x] = a_sbox[a ^ k2];
                tables[1][key_index][x] = b_sbox[context.x2[b] ^ k2];
                tables[2][key_index][x] = c_sbox[c ^ k2];
                tables[3][key_index][x] = d_sbox[context.x2[d] ^ k2];
            }
        }
    }
}

// ---------------------------------------------------------

static void compute_output_variables3(ExperimentContext &context,
                                      Array3D &tables,
                                      const size_t output_row_index,
                                      const size_t num_values) {
    Array a_sbox = context._1SBOX;
    Array b_sbox = context._1SBOX;
    Array c_sbox = context._3SBOX;
    Array d_sbox = context._2SBOX;

    if (output_row_index == 1) {
        a_sbox = context._1SBOX;
        b_sbox = context._3SBOX;
        c_sbox = context._2SBOX;
        d_sbox = context._1SBOX;
    } else if (output_row_index == 2) {
        a_sbox = context._3SBOX;
        b_sbox = context._2SBOX;
        c_sbox = context._1SBOX;
        d_sbox = context._1SBOX;
    } else if (output_row_index == 3) {
        a_sbox = context._2SBOX;
        b_sbox = context._1SBOX;
        c_sbox = context._1SBOX;
        d_sbox = context._3SBOX;
    }

    for (size_t k1 = 0; k1 < num_values; ++k1) {
        for (size_t k2 = 0; k2 < num_values; ++k2) {
            for (size_t x = 0; x < num_values; ++x) {
                const size_t a = context.a[k1][x];
                const size_t b = context.b[k1][x];
                const size_t c = context.c[k1][x];
                const size_t d = context.d[k1][x];
                const size_t key_index = (k2 * num_values) + k1;

                tables[0][key_index][x] = a_sbox[context.x3[a] ^ k2];
                tables[1][key_index][x] = b_sbox[b ^ k2];
                tables[2][key_index][x] = c_sbox[context.x3[c] ^ k2];
                tables[3][key_index][x] = d_sbox[d ^ k2];
            }
        }
    }
}

// ---------------------------------------------------------

static void compute_output_variables(ExperimentContext &context,
                                     Array3D &tables,
                                     const size_t config_index,
                                     const size_t output_row_index) {
    if (config_index == 0) {
        compute_output_variables0(context, tables, output_row_index,
                                  context.num_values);
    } else if (config_index == 1) {
        compute_output_variables1(context, tables, output_row_index,
                                  context.num_values);
    } else if (config_index == 2) {
        compute_output_variables2(context, tables, output_row_index,
                                  context.num_values);
    } else if (config_index == 3) {
        compute_output_variables3(context, tables, output_row_index,
                                  context.num_values);
    }
}

// ---------------------------------------------------------

static void compute_values_tables(ExperimentContext &context,
                                  Array3D &value_tables,
                                  const size_t input_index,
                                  const size_t output_index) {
    const size_t input_row_index = input_index % 4;
    const size_t input_column_index = input_index / 4;
    const size_t output_row_index = output_index % 4;
    const size_t output_column_index = output_index / 4;

    compute_input_variables(context, input_row_index);

    const size_t config_index =
        (8 + input_column_index - input_row_index - output_column_index) % 4;

    compute_output_variables(context,
                             value_tables,
                             config_index,
                             output_row_index);
}

// ---------------------------------------------------------

static void derive_difference_counts_table(Array &difference_counts_table,
                                           const Array2D &table,
                                           const size_t num_table_entries,
                                           const size_t x,
                                           const size_t x_prime) {
    zeroize_array(difference_counts_table);

    for (size_t i = 0; i < num_table_entries; ++i) {
        const size_t difference = table[i][x] ^table[i][x_prime];
        difference_counts_table[difference]++;
    }
}

// ---------------------------------------------------------

static void merge_difference_counts_tables(Array &result_table,
                                           const Array &left_table,
                                           const Array &right_table,
                                           const size_t num_values) {
    zeroize_array(result_table);

    for (size_t i = 0; i < num_values; ++i) {
        for (size_t j = 0; j < num_values; ++j) {
            const size_t difference = i ^j;
            const size_t num_combinations = left_table[i] * right_table[j];
            result_table[difference] += num_combinations;
        }
    }
}

// ---------------------------------------------------------

static size_t count_num_collisions_as_product(const Array &left_table,
                                              const Array &right_table,
                                              const size_t num_values) {
    size_t num_collisions = 0;

    for (size_t i = 0; i < num_values; ++i) {
        num_collisions += left_table[i] * right_table[i];
    }

    return num_collisions;
}

// ---------------------------------------------------------

static uint128_t count_num_collisions_as_sum(const Array2D &table,
                                             const size_t num_values,
                                             const size_t num_inner_values) {
    uint128_t num_collisions = 0;

    for (size_t i = 0; i < num_values; ++i) {
        for (size_t j = 0; j < num_inner_values; ++j) {
            num_collisions += table[i][j];
//            printf("# collisions[%3zu][%3zu] = %2zu\n", i, j, table[i][j]);
        }
    }

    return num_collisions;
}

// ---------------------------------------------------------

static uint128_t compute_num_collisions(ExperimentContext &context,
                                        const size_t input_index,
                                        const size_t output_index) {
    // ---------------------------------------------------------
    // Precompute the 4 tables L_i
    // Each entry of L_i maps 16 * 16 values of k = (K_0, K_1) to
    // a list of 16 values x: L_i[k][x].
    // ---------------------------------------------------------

    const size_t num_tables = 4;
    const size_t num_values = context.num_values;
    const size_t num_value_table_entries = num_values * num_values;

    Array3D value_tables(num_tables,
                         Array2D(num_value_table_entries,
                                 Array(num_values)));
    zeroize_3d_array(value_tables);

    compute_values_tables(context, value_tables, input_index, output_index);

    Array2D num_collisions_tables(num_values, Array(num_values));
    zeroize_2d_array(num_collisions_tables);

    Array2D difference_counts_tables(num_tables, Array(num_values));

    // ---------------------------------------------------------
    // Iterate over distinct binom(16, 2) pairs (x, x')
    // ---------------------------------------------------------

    for (size_t x = 0; x < num_values; ++x) {
        for (size_t x_prime = x + 1; x_prime < num_values; ++x_prime) {
            // ---------------------------------------------------------
            // For the current x, x', derive difference tables that map each
            // of the 16 differences to the number of its occurrence.
            // ---------------------------------------------------------

            for (size_t i = 0; i < num_tables; ++i) {
                derive_difference_counts_table(
                    difference_counts_tables[i],
                    value_tables[i],
                    num_value_table_entries,
                    x,
                    x_prime
                );
            }

            // ---------------------------------------------------------
            // Merge the 4 tables to 2
            // ---------------------------------------------------------

            Array difference_counts_0_1(num_values);
            Array difference_counts_2_3(num_values);

            merge_difference_counts_tables(difference_counts_0_1,
                                           difference_counts_tables[0],
                                           difference_counts_tables[1],
                                           num_values);
            merge_difference_counts_tables(difference_counts_2_3,
                                           difference_counts_tables[2],
                                           difference_counts_tables[3],
                                           num_values);

            // ---------------------------------------------------------
            // Merge the 2 tables, searching for collisions
            // ---------------------------------------------------------

            num_collisions_tables[x][x_prime] =
                count_num_collisions_as_product(difference_counts_0_1,
                                                difference_counts_2_3,
                                                num_values);
        }

        printf("# Finished x = %2zu\n", x);
    }

    return count_num_collisions_as_sum(num_collisions_tables,
                                       num_values,
                                       num_values);
}

// ---------------------------------------------------------

static void perform_experiments(ExperimentContext &context) {
    const size_t num_positions = context.num_positions;
    puts("# in-byte out-byte collisions");

    for (size_t input_index = context.input_start_index;
        input_index < num_positions;
        ++input_index) {
        for (size_t output_index = context.output_start_index;
             output_index < num_positions;
             ++output_index) {
            //
            const uint128_t num_collisions = compute_num_collisions(
                context, input_index, output_index
            );

            printf("%2zu %2zu ", input_index, output_index);
            std::cout << num_collisions << std::endl;
        }
    }
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static __m128i get_4bit_sbox(const size_t cipher_index) {
    switch (cipher_index) {
        case 0:
            return SMALL_AES_SBOX_1;

        case 1:
            return SMALL_AES_PRESENT_SBOX;
        case 2:
            return SMALL_AES_PRIDE_SBOX;
        case 3:
            return SMALL_AES_PRINCE_SBOX;
        case 4:
            return SMALL_AES_TOY6_SBOX;
        case 5:
            return SMALL_AES_TOY8_SBOX;
        case 6:
            return SMALL_AES_TOY10_SBOX;

        case 7:
            return SMALL_AES_RANDOM_SBOX0;
        case 8:
            return SMALL_AES_RANDOM_SBOX1;
        case 9:
            return SMALL_AES_RANDOM_SBOX2;
        case 10:
            return SMALL_AES_RANDOM_SBOX3;
        case 11:
            return SMALL_AES_RANDOM_SBOX4;

        case 12:
            return SMALL_AES_RANDOM_SBOX5;
        case 13:
            return SMALL_AES_RANDOM_SBOX6;
        case 14:
            return SMALL_AES_RANDOM_SBOX7;
        case 15:
            return SMALL_AES_RANDOM_SBOX8;
        case 16:
            return SMALL_AES_RANDOM_SBOX9;

        case 17:
            return SMALL_AES_RANDOM_SBOX10;
        case 18:
            return SMALL_AES_RANDOM_SBOX11;
        case 19:
            return SMALL_AES_RANDOM_SBOX12;
        case 20:
            return SMALL_AES_RANDOM_SBOX13;
        case 21:
            return SMALL_AES_RANDOM_SBOX14;

        case 22:
            return SMALL_AES_RANDOM_SBOX15;
        case 23:
            return SMALL_AES_RANDOM_SBOX16;
        case 24:
            return SMALL_AES_RANDOM_SBOX17;
        case 25:
            return SMALL_AES_RANDOM_SBOX18;
        case 26:
            return SMALL_AES_RANDOM_SBOX19;

        case 27:
            return _IDENTITY_SBOX;

        case 28:
            return _4_BIT_OPTIMAL_SBOX_0;
        case 29:
            return _4_BIT_OPTIMAL_SBOX_1;
        case 30:
            return _4_BIT_OPTIMAL_SBOX_2;
        case 31:
            return _4_BIT_OPTIMAL_SBOX_3;
        case 32:
            return _4_BIT_OPTIMAL_SBOX_4;
        case 33:
            return _4_BIT_OPTIMAL_SBOX_5;
        case 34:
            return _4_BIT_OPTIMAL_SBOX_6;
        case 35:
            return _4_BIT_OPTIMAL_SBOX_7;
        case 36:
            return _4_BIT_OPTIMAL_SBOX_8;
        case 37:
            return _4_BIT_OPTIMAL_SBOX_9;
        case 38:
            return _4_BIT_OPTIMAL_SBOX_10;
        case 39:
            return _4_BIT_OPTIMAL_SBOX_11;
        case 40:
            return _4_BIT_OPTIMAL_SBOX_12;
        case 41:
            return _4_BIT_OPTIMAL_SBOX_13;
        case 42:
            return _4_BIT_OPTIMAL_SBOX_14;
        case 43:
            return _4_BIT_OPTIMAL_SBOX_15;

        case 44:
            return _4_BIT_PLATINUM_SBOX_0_4_NUM_1_DL_CATEGORY_0;
        case 45:
            return _4_BIT_PLATINUM_SBOX_0_4_NUM_1_DL_CATEGORY_1;
        case 46:
            return _4_BIT_PLATINUM_SBOX_1_3_NUM_1_DL_CATEGORY_0;
        case 47:
            return _4_BIT_PLATINUM_SBOX_1_3_NUM_1_DL_CATEGORY_1;
        case 48:
            return _4_BIT_PLATINUM_SBOX_1_3_NUM_1_DL_CATEGORY_2;
        case 49:
            return _4_BIT_PLATINUM_SBOX_1_3_NUM_1_DL_CATEGORY_3;
        case 50:
            return _4_BIT_PLATINUM_SBOX_2_2_NUM_1_DL_CATEGORY_0;
        case 51:
            return _4_BIT_PLATINUM_SBOX_2_2_NUM_1_DL_CATEGORY_1;
        case 52:
            return _4_BIT_PLATINUM_SBOX_2_2_NUM_1_DL_CATEGORY_2;
        case 53:
            return _4_BIT_PLATINUM_SBOX_2_2_NUM_1_DL_CATEGORY_3;
        default:
            exit(EXIT_FAILURE);
    }
}

// ---------------------------------------------------------

static void to_array(Array &target, __m128i sbox) {
    const size_t NUM_BYTES = 16;

    uint8_t array[NUM_BYTES];
    storeu(array, sbox);

    target.resize(NUM_BYTES);

    for (size_t i = 0; i < NUM_BYTES; ++i) {
        target[i] = array[i];
    }
}

// ---------------------------------------------------------

static void to_array(Array &target,
                     const uint8_t *array,
                     const size_t num_values) {
    target.resize(num_values);

    for (size_t i = 0; i < num_values; ++i) {
        target[i] = array[i];
    }
}

// ---------------------------------------------------------

static bool is_4bit_sbox(const size_t cipher_index) {
    return cipher_index < NUM_4_BIT_SBOXES;
}

// ---------------------------------------------------------

static bool is_8bit_sbox(const size_t cipher_index) {
    return cipher_index - NUM_4_BIT_SBOXES < NUM_8_BIT_SBOXES;
}

// ---------------------------------------------------------

static void initialize_context_sboxes(ExperimentContext *context,
                                      const size_t cipher_index) {
    const size_t NUM_4_BIT_VALUES = 1 << 4;
    const size_t NUM_8_BIT_VALUES = 1 << 8;

    if (is_4bit_sbox(cipher_index)) {
        context->num_values = NUM_4_BIT_VALUES;

        const __m128i _1sbox = get_4bit_sbox(cipher_index);
        const __m128i _2sbox = vshuffle(_X2, _1sbox);
        const __m128i _3sbox = vshuffle(_X3, _1sbox);

        to_array(context->_1SBOX, _1sbox);
        to_array(context->_2SBOX, _2sbox);
        to_array(context->_3SBOX, _3sbox);

        to_array(context->x2, _X2);
        to_array(context->x3, _X3);
    } else if (is_8bit_sbox(cipher_index)) {
        context->num_values = NUM_8_BIT_VALUES;

        to_array(context->_1SBOX, ciphers::AES_SBOX, NUM_8_BIT_VALUES);
        to_array(context->_2SBOX, ciphers::AES_X2_SBOX, NUM_8_BIT_VALUES);
        to_array(context->_3SBOX, ciphers::AES_X3_SBOX, NUM_8_BIT_VALUES);

        to_array(context->x2, ciphers::AES_X2, NUM_8_BIT_VALUES);
        to_array(context->x3, ciphers::AES_X3, NUM_8_BIT_VALUES);
    }
}

// ---------------------------------------------------------

static void initialize_context(ExperimentContext *context,
                               const size_t cipher_index,
                               const size_t input_start_index,
                               const size_t output_start_index) {
    initialize_context_sboxes(context, cipher_index);
    context->num_positions = SMALL_AES_NUM_ROWS * SMALL_AES_NUM_COLUMNS;
    context->input_start_index = input_start_index;
    context->output_start_index = output_start_index;
    context->a = Array2D(context->num_values, Array(context->num_values));
    context->b = Array2D(context->num_values, Array(context->num_values));
    context->c = Array2D(context->num_values, Array(context->num_values));
    context->d = Array2D(context->num_values, Array(context->num_values));
}

// ---------------------------------------------------------

static void parse_args(ExperimentContext *context,
                       int argc,
                       const char **argv) {
    ArgumentParser parser;
    parser.appName(
        "Tests the number of collisions for all possible inputs to the "
        "Small-AES cell-to-cell four-round distinguisher. "
        "Cipher must be {0, ..., 53} for Small-AES with one of the following "
        "S-boxes (in that order):"
        "[Small-AES, PRESENT, PRIDE, PRINCE, TOY6, TOY8, TOY10, RANDOM0, ..., "
        "RANDOM19, Identity, Optimal0, ..., Optimal15, Platinum0, ..., "
        "Platinum9]\n"
        "Alternatively, in {54} for the AES.");
    parser.addArgument("-c", "--cipher", 1, false);
    parser.addArgument("-i", "--input_start_index", 1, false);
    parser.addArgument("-o", "--output_start_index", 1, false);

    try {
        parser.parse((size_t) argc, argv);

        const size_t cipher_index = parser.retrieveAsLong("c");
        const size_t input_start_index = parser.retrieveAsLong("i");
        const size_t output_start_index = parser.retrieveAsLong("o");

        if (cipher_index > 54) {
            std::cerr << "Cipher index must be in {0, ..., 54}." << std::endl;
            exit(EXIT_FAILURE);
        } else {
            initialize_context(
                context, cipher_index, input_start_index, output_start_index
            );
        }
    } catch (...) {
        std::cerr << parser.usage() << std::endl;
        exit(EXIT_FAILURE);
    }
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(&context, argc, argv);
    perform_experiments(context);
    return EXIT_SUCCESS;
}
