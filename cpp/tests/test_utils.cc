/**
 * __author__ = anonymized
 * __date__   = 2019-03-31
 * __copyright__ = CC0
 */

#include <gtest/gtest.h>
#include <stdint.h>

#include "utils/utils.h"


using namespace utils;

// ---------------------------------------------------------

TEST(Utils, convert_to_uint64) {
    const __m128i value = vsetr8(
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    );
    const uint64_t expected = 0x0123456789abcdef;
    const uint64_t actual = convert_to_uint64(value);
    ASSERT_EQ(expected, actual);
}

// ---------------------------------------------------------

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
