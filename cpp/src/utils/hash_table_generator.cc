/**
 * Utility functions.
 *
 * __author__ = anonymous
 * __date__   = 2018-05
 * __copyright__ = Creative Commons CC0
 */

#include <cassert>

#include "ciphers/small_aes.h"
#include "utils/hash_table_generator.h"
#include "utils/product.h"

using namespace ciphers;

// ---------------------------------------------------------------------

namespace utils {

    static size_t extract_column(const small_aes_state_t state,
                                 const size_t column_index) {
        const size_t byte_index = 2 * column_index;
        return (state[byte_index] << 8) | state[byte_index + 1];
    }

    // ---------------------------------------------------------------------

    static size_t invert_mixcolumns(const uint8_t gamma,
                                    const size_t active_cell_index) {
        // 1-nibble difference
        __m128i state = zero;

        if (active_cell_index == 0) {
            state = vset8_single0(gamma);
        } else if (active_cell_index == 1) {
            state = vset8_single1(gamma);
        } else if (active_cell_index == 2) {
            state = vset8_single2(gamma);
        } else if (active_cell_index == 3) {
            state = vset8_single3(gamma);
        }

        // Invert MixColumns
        state = small_aes_invert_mix_columns(state);
        small_aes_state_t text;
        to_byte_array(text, state);

        // Return column as int
        return extract_column(text, 0);
    }

    // ---------------------------------------------------------------------

    void HashTableGenerator::create_hash_table(
        ExtendedDDT& hash_table,
        const size_t active_cell_index,
        const ExtendedDDT& extended_ddt) {

        const size_t num_bits = 4;
        const size_t num_values = 1 << num_bits; // 16
        const size_t num_column_values = 1 << 16;

        IntegerList betas(num_values, 0);

        // For all 1-nibble differences gamma, get the differences
        // beta = MC^{-1}(gamma).
        for (size_t gamma = 1; gamma < num_values; ++gamma) {
            betas[gamma] = invert_mixcolumns(gamma, active_cell_index);
        }

        hash_table.clear();

        for (size_t alpha = 0; alpha < num_column_values; ++alpha) {
            IntegerMatrix transitions;
            get_transitions(transitions, alpha, betas, extended_ddt);
            hash_table.push_back(transitions);
        }
    }

    // ---------------------------------------------------------------------

    size_t to_single_value(const IntegerList& column) {
        assert(column.size() >= 4);
        return ((column[0] & 0xF) << 12)
            | ((column[1] & 0xF) << 8)
            | ((column[2] & 0xF) << 4)
            | (column[3] & 0xF);
    }

    // ---------------------------------------------------------------------

    void HashTableGenerator::get_transitions(
        IntegerMatrix& possible_transitions,
        const size_t alpha,
        const IntegerList& betas,
        const ExtendedDDT& extended_ddt) {

        const size_t num_bits = 4;
        const size_t num_values = 1 << num_bits;

        possible_transitions.clear();

        for (size_t i = 1; i < num_values; ++i) {
            const size_t beta = betas[i];
            IntegerMatrix transitions;
            bool do_continue = false;

            for (size_t j = 0; j < 4; ++j) {
                const size_t alpha_i = (alpha >> ((3 - j) * num_bits)) & 0xF;
                const size_t beta_i = (beta >> ((3 - j) * num_bits)) & 0xF;
                const IntegerList& possible_values = extended_ddt[alpha_i][beta_i];

                if (possible_values.empty()) {
                    do_continue = true;
                    break;
                }

                transitions.push_back(possible_values);
            }

            // 1111 => [
            // (12, 0, 2, 14), (12, 0, 2, 15), (12, 0, 3, 14), (12, 0, 3, 15),
            // (12, 1, 2, 14), (12, 1, 2, 15), (12, 1, 3, 14), (12, 1, 3, 15),
            // (13, 0, 2, 14), (13, 0, 2, 15), (13, 0, 3, 14), (13, 0, 3, 15),
            // (13, 1, 2, 14), (13, 1, 2, 15), (13, 1, 3, 14), (13, 1, 3, 15)
            // ]

            // Translate transitions [x0,x1,x2,x3] to integers
            // x = (x0 || x1 || x2 || x3).

            if (do_continue) {
                continue;
            }

            build_product(possible_transitions, transitions);
        }
    }

    // ---------------------------------------------------------------------

    void HashTableGenerator::compute_extended_ddt(
        ExtendedDDT& extended_ddt,
        const size_t* sbox,
        const size_t num_entries) {

        extended_ddt.clear();

        for (size_t delta_x = 0; delta_x < num_entries; ++delta_x) {
            IntegerMatrix matrix;

            for (size_t delta_y = 0; delta_y < num_entries; ++delta_y) {
                IntegerList vector;
                matrix.push_back(vector);
            }

            extended_ddt.push_back(matrix);
        }

        for (size_t x = 0; x < num_entries; ++x) {
            size_t y = sbox[x];

            for (size_t delta_x = 0; delta_x < num_entries; ++delta_x) {
                size_t x_prime = x ^ delta_x;
                size_t y_prime = sbox[x_prime];
                size_t delta_y = y ^ y_prime;

                IntegerList& entry = extended_ddt[delta_x][delta_y];
                entry.push_back(x);
            }
        }
    }

    // ---------------------------------------------------------

    void HashTableGenerator::print_extended_ddt(
        const ExtendedDDT& extended_ddt,
        const size_t num_entries) {

        for (size_t delta_x = 0; delta_x < num_entries; ++delta_x) {
            for (size_t delta_y = 0; delta_y < num_entries; ++delta_y) {
                const IntegerList& values_i_j = extended_ddt[delta_x][delta_y];
                printf("[%01lx][%01lx]: ", delta_x, delta_y);

                for (size_t k = 0; k < values_i_j.size(); ++k) {
                    printf("%01lx, ", values_i_j[k]);
                }

                puts("");
            }
        }
    }


}
