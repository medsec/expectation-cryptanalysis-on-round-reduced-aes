/**
 * Utility functions.
 *
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#include "utils/product.h"

// ---------------------------------------------------------------------

namespace utils {

    static void build_subproduct(std::vector<IntegerList>& result,
                                 IntegerList& prefix,
                                 size_t current_index,
                                 const std::vector<IntegerList>& lists) {
        const IntegerList& current_list = lists[current_index];
        const size_t num_lists = lists.size();

        for (size_t i = 0; i < current_list.size(); ++i) {
            IntegerList new_prefix = prefix;
            new_prefix.push_back(current_list[i]);

            if (current_index + 1 < num_lists) {
                build_subproduct(result, new_prefix, current_index + 1, lists);
            } else {
                result.push_back(new_prefix);
            }
        }
    }

    // ---------------------------------------------------------------------

    void build_product(std::vector<IntegerList>& result,
                       const std::vector<IntegerList>& lists) {
        const size_t current_index = 0;
        IntegerList prefix;
        build_subproduct(result, prefix, current_index, lists);
    }

}