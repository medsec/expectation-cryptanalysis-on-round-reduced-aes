/**
 * Implements the product functionality from Python's itertools.
 *
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#ifndef _PRODUCT_H
#define _PRODUCT_H

#include <vector>
#include <cstddef>

#include "utils/utils.h"

// ---------------------------------------------------------------------

namespace utils {

    void build_product(std::vector<IntegerList >& result,
                       const std::vector<IntegerList >& lists);

}

// ---------------------------------------------------------------------

#endif //_PRODUCT_H
