/**
 * __author__ = anonymous
 * __date__   = 2018-05
 * __copyright__ = Creative Commons CC0
 */ 

// ---------------------------------------------------------------------

#include <smmintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "utils/utils.h"

// ---------------------------------------------------------------------

namespace utils {

    void print_128(const char *label, const __m128i variable) {
        uint8_t val[16];
        storeu((void *) val, variable);
        printf("%s ", label);

        for (size_t i = 0; i < 16; ++i) {
            printf("%02x", val[i]);
        }

        puts("");
    }

    // ---------------------------------------------------------------------

    void print_256(const char *label, const __m256i variable) {
        uint8_t val[32];
        avxstoreu((void *) val, variable);
        printf("%s ", label);

        for (size_t i = 0; i < 32; ++i) {
            printf("%02x", val[i]);
        }

        puts("");
    }

    // ---------------------------------------------------------------------

    void print_hex(const char *label,
                   const uint8_t *array,
                   const size_t num_bytes) {
        printf("%s: ", label);

        for (size_t i = 0; i < num_bytes; i++) {
            if ((i != 0) && (i % 16 == 0)) {
                puts("");
            }

            printf("%02x", array[i]);
        }

        puts("");
    }

    // ---------------------------------------------------------------------

    bool assert_equal(const uint8_t *expected,
                      const uint8_t *actual,
                      const size_t num_expected_bytes,
                      const size_t num_actual_bytes) {
        if (num_expected_bytes != num_actual_bytes) {
            return false;
        }

        if (!memcmp(expected, actual, num_expected_bytes)) {
            return true;
        }

        print_hex("Expected", expected, num_expected_bytes);
        print_hex("But was ", actual, num_actual_bytes);
        return false;
    }

    // ---------------------------------------------------------------------

    bool assert_equal(const uint8_t *expected,
                      const uint8_t *actual,
                      const size_t num_bytes) {
        return assert_equal(expected, actual, num_bytes, num_bytes);
    }

    // ---------------------------------------------------------

    void to_uint8(uint8_t* target, const uint32_t* src, size_t num_bytes) {
        for (size_t i = 0; i < num_bytes/4; i++) {
            target[i*4  ] = (uint8_t)((src[i] >> 24) & 0xFF);
            target[i*4+1] = (uint8_t)((src[i] >> 16) & 0xFF);
            target[i*4+2] = (uint8_t)((src[i] >>  8) & 0xFF);
            target[i*4+3] =  (uint8_t)(src[i] & 0xFF);
        }
    }

    // ---------------------------------------------------------

    void to_uint32(uint32_t* target, const uint8_t* src, size_t num_bytes) {
        for (size_t i = 0; i < num_bytes/4; i++) {
            target[i] = ((uint32_t)(src[i*4  ]) << 24)
                | ((uint32_t)(src[i*4+1]) << 16)
                | ((uint32_t)(src[i*4+2]) <<  8)
                | ((uint32_t)(src[i*4+3]));
        }
    }

    // ---------------------------------------------------------

    void to_uint64(uint64_t* target,
                   const uint8_t* src,
                   size_t num_bytes) {
        for (size_t i = 0; i < num_bytes/8; i++) {
            target[i] = ((uint64_t)(src[i*8  ]) << 56)
                | ((uint64_t)(src[i*8+1]) << 48)
                | ((uint64_t)(src[i*8+2]) << 40)
                | ((uint64_t)(src[i*8+3]) << 32)
                | ((uint64_t)(src[i*8+4]) << 24)
                | ((uint64_t)(src[i*8+5]) << 16)
                | ((uint64_t)(src[i*8+6]) <<  8)
                | ((uint64_t)(src[i*8+7]));
        }
    }

    // ---------------------------------------------------------------------

    uint64_t convert_to_uint64(const __m128i source) {
        __m128i lo = vand(
            source, vset32(0x000F000F, 0x000F000F, 0x000F000F, 0x000F000F)
        );
        __m128i hi = vand(
            source, vset32(0x0F000F00, 0x0F000F00, 0x0F000F00, 0x0F000F00)
        );
        lo = vxor(vshiftleft16(lo, 12), hi);
        lo = vshuffle(lo,
                      vsetr8(15, 13, 11, 9, 7, 5, 3, 1,
                             (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF,
                             (uint8_t) 0xFF, (uint8_t) 0xFF, (uint8_t) 0xFF,
                             (uint8_t) 0xFF, (uint8_t) 0xFF)
        );
        return (uint64_t) vget64(lo, 0);
    }

    // ---------------------------------------------------------------------

    void xor_arrays(uint8_t *target,
                    const uint8_t *left,
                    const uint8_t *right,
                    const size_t num_bytes) {
        for (size_t i = 0; i < num_bytes; ++i) {
            target[i] = left[i] ^ right[i];
        }
    }

    // ---------------------------------------------------------------------

    void zeroize_array(uint8_t *target,
                       size_t num_bytes) {
        memset(target, 0x00, num_bytes);
    }

}
