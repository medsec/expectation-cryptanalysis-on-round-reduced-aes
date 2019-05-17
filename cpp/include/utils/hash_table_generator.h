/**
 * Generates the hash tables for the AES.
 *
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#ifndef _HASH_TABLE_GENERATOR_H_
#define _HASH_TABLE_GENERATOR_H_

#include <string>
#include <vector>

#include "utils/utils.h"

// ---------------------------------------------------------------------

namespace utils {

    class HashTableGenerator {

    public:

        void create_hash_table(
            ExtendedDDT& hash_table,
            size_t active_cell_index,
            const ExtendedDDT& extended_ddt);

        // ---------------------------------------------------------------------

        void get_transitions(
            IntegerMatrix& possible_transitions,
            size_t alpha,
            const IntegerList& betas,
            const ExtendedDDT& extended_ddt);

        // ---------------------------------------------------------------------

        void compute_extended_ddt(
            ExtendedDDT& extended_ddt,
            const size_t* sbox,
            size_t num_entries);

        // ---------------------------------------------------------------------

        void print_extended_ddt(const ExtendedDDT& extended_ddt,
                                size_t num_entries);

    };

}

// ---------------------------------------------------------------------

#endif  // _HASH_TABLE_GENERATOR_H_
