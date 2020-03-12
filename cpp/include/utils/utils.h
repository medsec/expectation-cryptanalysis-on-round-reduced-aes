/**
 * Utility functions.
 *
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#ifndef _UTILS_H_
#define _UTILS_H_

// ---------------------------------------------------------------------

#include <xmmintrin.h> // SSE
#include <emmintrin.h> // SSE2
#include <pmmintrin.h> // SSE3
#include <tmmintrin.h> // SSSE3
#include <smmintrin.h> // SSE4.1
#include <nmmintrin.h> // SSE4.2
#include <wmmintrin.h> // AES
#include <immintrin.h> // AVX

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>

// ---------------------------------------------------------------------

namespace utils {

    typedef std::vector<size_t> IntegerList; // 1D
    typedef std::vector<IntegerList> IntegerMatrix; // 2D
    typedef IntegerMatrix DDT; // 2D
    typedef std::vector<IntegerMatrix> ExtendedDDT; // 3D

// ---------------------------------------------------------------------

#if __GNUC__
#define ALIGN(n)      __attribute__ ((aligned(n)))
#elif _MSC_VER
#define ALIGN(n)      __declspec(align(n))
#else
#define ALIGN(n)
#endif

// ---------------------------------------------------------------------

#define loadu(p)       _mm_loadu_si128((__m128i*)p)
#define load(p)        _mm_load_si128((__m128i*)p)
#define storeu(p, x)   _mm_storeu_si128((__m128i*)p, x)
#define store(p, x)    _mm_store_si128((__m128i*)p, x)
#define zero           _mm_setzero_si128()
#define vand(x, y)     _mm_and_si128(x, y)
#define vxor(x, y)     _mm_xor_si128(x, y)
#define vor(x, y)      _mm_or_si128(x, y)

// Sets (high to low) x15, x4, ..., x0
#define vset8(x15, x14, x13, x12, x11, x10, x9, x8, x7, x6, x5, x4, x3, x2, x1, x0) \
    _mm_set_epi8(x15, x14, x13, x12, x11, x10, x9, x8, x7, x6, x5, x4, x3, x2, x1, x0)

// Sets (high to low) x0, x1, ..., x15
#define vsetr8(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15) \
    _mm_setr_epi8(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15)

#define vset8_single(x)  _mm_set1_epi8(x)
#define vset8_single0(x) _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, x)
#define vset8_single1(x) _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, x, 0)
#define vset8_single2(x) _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, x, 0, 0)
#define vset8_single3(x) _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, x, 0, 0, 0)

// Given an integer array [x0, x1, ..., x15] turns it into
// an m128i register with [x15, x14, ..., x0].
// If it is stored into a byte array, the order is again inverted.
#define vset64(x0, x1)              _mm_set_epi64((__m64)x1, (__m64)x0)
#define vset32(x0, x1, x2, x3)      _mm_set_epi32(x3, x2, x1, x0)
#define vget64(x, i)                _mm_extract_epi64(x, i)
#define vshiftleft16(x, shift)      _mm_slli_epi16(x, shift)
#define vshiftright16(x, shift)     _mm_srli_epi16(x, shift)
#define vshiftleft32(x, shift)      _mm_slli_epi32(x, shift)
#define vshiftright32(x, shift)     _mm_srli_epi32(x, shift)
#define vshiftleft64(x, shift)      _mm_slli_epi64(x, shift)
#define vshiftright64(x, shift)     _mm_srli_epi64(x, shift)

// Some old compilers lack the _mm_bslli_si128/_mm_bsrli_si128 intrinsics
// https://stackoverflow.com/questions/34478328/the-best-way-to-shift-a-m128i

#define vshiftleft_bytes(x, shift)  _mm_slli_si128(x, shift)
#define vshiftright_bytes(x, shift) _mm_srli_si128(x, shift)

#define vshuffle(x, mask)           _mm_shuffle_epi8(x, mask)
#define vunpacklo8(x, y)            _mm_unpacklo_epi8(x, y)
#define vunpackhi8(x, y)            _mm_unpackhi_epi8(x, y)
#define vblend8(x, y, mask)         _mm_blendv_epi8(x, y, mask)
#define vis_zero(x)                 (_mm_testc_si128(zero, x) && _mm_testz_si128(zero, x))
#define vare_equal(x, y)            vis_zero(vxor(x, y))

#define vxor4values(a, b, c, d)     vxor(vxor(a, b), vxor(c, d))
#define vxor4(x, y) {\
    x[0] = vxor(x[0], y[0]);\
    x[1] = vxor(x[1], y[1]);\
    x[2] = vxor(x[2], y[2]);\
    x[3] = vxor(x[3], y[3]);\
}

    // ---------------------------------------------------------
    // Definitions for AVX
    // ---------------------------------------------------------

#define avxloadu(p)                 _mm256_load_si256((__m128i*)p)
#define avxload(p)                  _mm256_load_si256((__m256i*)p)
#define avxstoreu(p, x)             _mm256_storeu_si256((__m256i*)p, x)
#define avxstore(p, x)              _mm256_store_si256((__m256i*)p, x)

    // ---------------------------------------------------------
    // The following defines target AVX-1 platforms, AVX-2 have the proper
    // _si256 intrinsics, e.g. _mm256_xor_si256
    // ---------------------------------------------------------

#ifdef __AVX2__
    #define avxzero                     _mm256_setzero_si256()
    #define avxand(x, y)                _mm256_and_si256(x, y)
    #define avxxor(x, y)                _mm256_xor_si256(x, y)
    #define avxor(x, y)                 _mm256_or_si256(x, y)
    #define avxshuffle(x, mask)         _mm256_shuffle_epi8(x, mask)
    #define avxis_zero(x)               (_mm256_testc_si256(avxzero, x) && _mm256_testz_si256(avxzero, x))

    #define vget128(x, i)               _mm256_extracti128_si256(x, i)
    #define vset128(x0, x1)             _mm256_set_m128i(x1, x0)
#elif defined(__AVX__)
    #define avx_to_float(x)             _mm256_castsi256_ps(x)
    #define avx_to_int(x)               _mm256_castps_si256(x)
    #define avxzero                     avx_to_int(_mm256_setzero_ps())
    #define avxand(x, y)                avx_to_int(_mm256_and_ps(avx_to_float(x), avx_to_float(y)))
    #define avxxor(x, y)                avx_to_int(_mm256_xor_ps(avx_to_float(x), avx_to_float(y)))
    #define avxor(x, y)                 avx_to_int(_mm256_or_ps(avx_to_float(x), avx_to_float(y)))

    // Some old compilers lack the _mm256_set_m128i intrinsic
    // https://stackoverflow.com/questions/32630458/setting-m256i-to-the-value-of-two-m128i-values

    #define vget128(x, i)               _mm256_extractf128_si256(x, i)
    #define vset128(v0, v1)             _mm256_insertf128_si256(_mm256_castsi128_si256(v0), (v1), 1)

    #define avxshuffle(x, mask)         vset128(vshuffle(vget128(x, 0), vget128(mask, 0)), vshuffle(vget128(x, 1), vget128(mask, 1)))
#endif


    // ---------------------------------------------------------
    // Definitions for non-SSE
    // ---------------------------------------------------------

#define ROTL32(x, n) (x<<n | x>>(32-n))
#define ROTR32(x, n) (x>>n | x<<(32-n))

    // ---------------------------------------------------------
    // Assertions
    // ---------------------------------------------------------

    bool assert_equal(const uint8_t *expected,
                      const uint8_t *actual,
                      size_t num_bytes);

    // ---------------------------------------------------------------------

    bool assert_equal(const uint8_t *expected,
                      const uint8_t *actual,
                      size_t num_expected_bytes,
                      size_t num_actual_bytes);

    // ---------------------------------------------------------------------

    double compute_mean(const std::vector<size_t>& values);

    // ---------------------------------------------------------------------

    double compute_variance(const std::vector<size_t>& values);

    // ---------------------------------------------------------------------

    double compute_standard_deviation(const std::vector<size_t>& values);

    // ---------------------------------------------------------
    // Printing
    // ---------------------------------------------------------

    void print_128(const char *label, __m128i variable);

    // ---------------------------------------------------------------------

    void print_256(const char *label, __m256i variable);

    // ---------------------------------------------------------------------

    void print_hex(const char *label, const uint8_t *array, size_t num_bytes);

    // ---------------------------------------------------------
    // Endian-correct conversion
    // ---------------------------------------------------------

    void to_uint8(uint8_t *target,
                  const uint32_t *src,
                  size_t num_bytes);

    // ---------------------------------------------------------

    void to_uint32(uint32_t *target,
                   const uint8_t *src,
                   size_t num_bytes);

    // ---------------------------------------------------------

    void to_uint64(uint64_t *target,
                   const uint8_t *src,
                   size_t num_bytes);

    // ---------------------------------------------------------

    /**
     * Given a 16-byte string [x15, x14, ..., x0],
     * where only the least significant four bits (nibble) of each byte are set,
     * returns the set 64 bits as uint such that the result is
     * [x0_lo || x1_lo || ... || x15_lo].
     * @param source
     * @return
     */
    uint64_t convert_to_uint64(__m128i source);

    // ---------------------------------------------------------------------

    void xor_arrays(uint8_t *target,
                    const uint8_t *left,
                    const uint8_t *right,
                    size_t num_bytes);

    // ---------------------------------------------------------------------

    void zeroize_array(uint8_t *target,
                       size_t num_bytes);

    // ---------------------------------------------------------------------

}

#endif  // _UTILS_H_
