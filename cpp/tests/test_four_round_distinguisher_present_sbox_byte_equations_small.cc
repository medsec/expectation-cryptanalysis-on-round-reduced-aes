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
#include "ciphers/small_aes.h"
#include "ciphers/small_state.h"
#include "ciphers/speck64.h"
#include "utils/argparse.h"
#include "utils/utils.h"
#include "utils/xorshift1024.h"

using utils::ArgumentParser;

// ---------------------------------------------------------

typedef struct {
} ExperimentContext;

// ---------------------------------------------------------
// Constants
// ---------------------------------------------------------

#define _1SBOX vsetr8(0x0c, 0x05, 0x06, 0x0b, 0x09, 0x00, 0x0a, 0x0d, 0x03, 0x0e, 0x0f, 0x08, 0x04, 0x07, 0x01, 0x02)
#define _2SBOX vsetr8(0x0b, 0x0a, 0x0c, 0x05, 0x01, 0x00, 0x07, 0x09, 0x06, 0x0f, 0x0d, 0x03, 0x08, 0x0e, 0x02, 0x04)
#define _3SBOX vsetr8(0x07, 0x0f, 0x0a, 0x0e, 0x08, 0x00, 0x0d, 0x04, 0x05, 0x01, 0x02, 0x0b, 0x0c, 0x09, 0x03, 0x06)

#define _X1    vsetr8(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f)
#define _X2    vsetr8(0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x03, 0x01, 0x07, 0x05, 0x0b, 0x09, 0x0f, 0x0d)
#define _X3    vsetr8(0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02)

// ---------------------------------------------------------
// Macros
// ---------------------------------------------------------

/**
 *
 * @param x    [0, 1, ..., 15]
 * @param k1_0 [v, v, ..., v] = 16 times the same current value of K^1[0]
 * @param k1_1
 * @param k1_2
 * @param k1_3
 * @param k2_0
 * @param k2_1
 * @param k2_2
 * @param k2_3 [v, v, ..., v] = 16 times the same current value of K^2[3]
 * @param e    [e_0, e_1, ..., e_15] = Array of results for the 16 output
 * byte indices where e_i is the result of [e_i[0], ..., e_i[15]], and
 * e_i[x] the result for the value of x.
 */
static void finalize_config0(__m128i abcd[4],
                             __m128i _2abcd[4],
                             __m128i _3abcd[4],
                             __m128i e[16]) {
    e[0] = vxor4values(vshuffle(_2SBOX, _2abcd[0]), vshuffle(_3SBOX, abcd[3]),
                       vshuffle(_1SBOX, _2abcd[2]), vshuffle(_1SBOX, abcd[1]));
    e[1] = vxor4values(vshuffle(_1SBOX, _2abcd[0]), vshuffle(_2SBOX, abcd[3]),
                       vshuffle(_3SBOX, _2abcd[2]), vshuffle(_1SBOX, abcd[1]));
    e[2] = vxor4values(vshuffle(_1SBOX, _2abcd[0]), vshuffle(_1SBOX, abcd[3]),
                       vshuffle(_2SBOX, _2abcd[2]), vshuffle(_3SBOX, abcd[1]));
    e[3] = vxor4values(vshuffle(_3SBOX, _2abcd[0]), vshuffle(_1SBOX, abcd[3]),
                       vshuffle(_1SBOX, _2abcd[2]), vshuffle(_2SBOX, abcd[1]));

    e[4] = vxor4values(vshuffle(_2SBOX, abcd[3]), vshuffle(_3SBOX, _3abcd[2]),
                       vshuffle(_1SBOX, abcd[1]), vshuffle(_1SBOX, _3abcd[0]));
    e[5] = vxor4values(vshuffle(_1SBOX, abcd[3]), vshuffle(_2SBOX, _3abcd[2]),
                       vshuffle(_3SBOX, abcd[1]), vshuffle(_1SBOX, _3abcd[0]));
    e[6] = vxor4values(vshuffle(_1SBOX, abcd[3]), vshuffle(_1SBOX, _3abcd[2]),
                       vshuffle(_2SBOX, abcd[1]), vshuffle(_3SBOX, _3abcd[0]));
    e[7] = vxor4values(vshuffle(_3SBOX, abcd[3]), vshuffle(_1SBOX, _3abcd[2]),
                       vshuffle(_1SBOX, abcd[1]), vshuffle(_2SBOX, _3abcd[0]));

    e[8] = vxor4values(vshuffle(_2SBOX, abcd[2]), vshuffle(_3SBOX, _2abcd[1]),
                       vshuffle(_1SBOX, abcd[0]), vshuffle(_1SBOX, _2abcd[3]));
    e[9] = vxor4values(vshuffle(_1SBOX, abcd[2]), vshuffle(_2SBOX, _2abcd[1]),
                       vshuffle(_3SBOX, abcd[0]), vshuffle(_1SBOX, _2abcd[3]));
    e[10] = vxor4values(vshuffle(_1SBOX, abcd[2]), vshuffle(_1SBOX, _2abcd[1]),
                        vshuffle(_2SBOX, abcd[0]), vshuffle(_3SBOX, _2abcd[3]));
    e[11] = vxor4values(vshuffle(_3SBOX, abcd[2]), vshuffle(_1SBOX, _2abcd[1]),
                        vshuffle(_1SBOX, abcd[0]), vshuffle(_2SBOX, _2abcd[3]));

    e[12] = vxor4values(vshuffle(_2SBOX, _3abcd[1]), vshuffle(_3SBOX, abcd[0]),
                        vshuffle(_1SBOX, _3abcd[3]), vshuffle(_1SBOX, abcd[2]));
    e[13] = vxor4values(vshuffle(_1SBOX, _3abcd[1]), vshuffle(_2SBOX, abcd[0]),
                        vshuffle(_3SBOX, _3abcd[3]), vshuffle(_1SBOX, abcd[2]));
    e[14] = vxor4values(vshuffle(_1SBOX, _3abcd[1]), vshuffle(_1SBOX, abcd[0]),
                        vshuffle(_2SBOX, _3abcd[3]), vshuffle(_3SBOX, abcd[2]));
    e[15] = vxor4values(vshuffle(_3SBOX, _3abcd[1]), vshuffle(_1SBOX, abcd[0]),
                        vshuffle(_1SBOX, _3abcd[3]), vshuffle(_2SBOX, abcd[2]));
}

// ---------------------------------------------------------

static void finalize_config1(__m128i abcd[4],
                             __m128i _2abcd[4],
                             __m128i _3abcd[4],
                             __m128i e[16]) {
    e[0] = vxor4values(vshuffle(_2SBOX, abcd[3]), vshuffle(_3SBOX, _3abcd[2]),
                       vshuffle(_1SBOX, abcd[1]), vshuffle(_1SBOX, _3abcd[0]));
    e[1] = vxor4values(vshuffle(_1SBOX, abcd[3]), vshuffle(_2SBOX, _3abcd[2]),
                       vshuffle(_3SBOX, abcd[1]), vshuffle(_1SBOX, _3abcd[0]));
    e[2] = vxor4values(vshuffle(_1SBOX, abcd[3]), vshuffle(_1SBOX, _3abcd[2]),
                       vshuffle(_2SBOX, abcd[1]), vshuffle(_3SBOX, _3abcd[0]));
    e[3] = vxor4values(vshuffle(_3SBOX, abcd[3]), vshuffle(_1SBOX, _3abcd[2]),
                       vshuffle(_1SBOX, abcd[1]), vshuffle(_2SBOX, _3abcd[0]));

    e[4] = vxor4values(vshuffle(_2SBOX, abcd[2]), vshuffle(_3SBOX, _2abcd[1]),
                       vshuffle(_1SBOX, abcd[0]), vshuffle(_1SBOX, _2abcd[3]));
    e[5] = vxor4values(vshuffle(_1SBOX, abcd[2]), vshuffle(_2SBOX, _2abcd[1]),
                       vshuffle(_3SBOX, abcd[0]), vshuffle(_1SBOX, _2abcd[3]));
    e[6] = vxor4values(vshuffle(_1SBOX, abcd[2]), vshuffle(_1SBOX, _2abcd[1]),
                       vshuffle(_2SBOX, abcd[0]), vshuffle(_3SBOX, _2abcd[3]));
    e[7] = vxor4values(vshuffle(_3SBOX, abcd[2]), vshuffle(_1SBOX, _2abcd[1]),
                       vshuffle(_1SBOX, abcd[0]), vshuffle(_2SBOX, _2abcd[3]));

    e[8] = vxor4values(vshuffle(_2SBOX, _3abcd[1]), vshuffle(_3SBOX, abcd[0]),
                       vshuffle(_1SBOX, _3abcd[3]), vshuffle(_1SBOX, abcd[2]));
    e[9] = vxor4values(vshuffle(_1SBOX, _3abcd[1]), vshuffle(_2SBOX, abcd[0]),
                       vshuffle(_3SBOX, _3abcd[3]), vshuffle(_1SBOX, abcd[2]));
    e[10] = vxor4values(vshuffle(_1SBOX, _3abcd[1]), vshuffle(_1SBOX, abcd[0]),
                        vshuffle(_2SBOX, _3abcd[3]), vshuffle(_3SBOX, abcd[2]));
    e[11] = vxor4values(vshuffle(_3SBOX, _3abcd[1]), vshuffle(_1SBOX, abcd[0]),
                        vshuffle(_1SBOX, _3abcd[3]), vshuffle(_2SBOX, abcd[2]));

    e[12] = vxor4values(vshuffle(_2SBOX, _2abcd[0]), vshuffle(_3SBOX, abcd[3]),
                        vshuffle(_1SBOX, _2abcd[2]), vshuffle(_1SBOX, abcd[1]));
    e[13] = vxor4values(vshuffle(_1SBOX, _2abcd[0]), vshuffle(_2SBOX, abcd[3]),
                        vshuffle(_3SBOX, _2abcd[2]), vshuffle(_1SBOX, abcd[1]));
    e[14] = vxor4values(vshuffle(_1SBOX, _2abcd[0]), vshuffle(_1SBOX, abcd[3]),
                        vshuffle(_2SBOX, _2abcd[2]), vshuffle(_3SBOX, abcd[1]));
    e[15] = vxor4values(vshuffle(_3SBOX, _2abcd[0]), vshuffle(_1SBOX, abcd[3]),
                        vshuffle(_1SBOX, _2abcd[2]), vshuffle(_2SBOX, abcd[1]));
}

// ---------------------------------------------------------

static void finalize_config2(__m128i abcd[4],
                             __m128i _2abcd[4],
                             __m128i _3abcd[4],
                             __m128i e[16]) {
    e[0] = vxor4values(vshuffle(_2SBOX, abcd[2]), vshuffle(_3SBOX, _2abcd[1]),
                       vshuffle(_1SBOX, abcd[0]), vshuffle(_1SBOX, _2abcd[3]));
    e[1] = vxor4values(vshuffle(_1SBOX, abcd[2]), vshuffle(_2SBOX, _2abcd[1]),
                       vshuffle(_3SBOX, abcd[0]), vshuffle(_1SBOX, _2abcd[3]));
    e[2] = vxor4values(vshuffle(_1SBOX, abcd[2]), vshuffle(_1SBOX, _2abcd[1]),
                       vshuffle(_2SBOX, abcd[0]), vshuffle(_3SBOX, _2abcd[3]));
    e[3] = vxor4values(vshuffle(_3SBOX, abcd[2]), vshuffle(_1SBOX, _2abcd[1]),
                       vshuffle(_1SBOX, abcd[0]), vshuffle(_2SBOX, _2abcd[3]));

    e[4] = vxor4values(vshuffle(_2SBOX, _3abcd[1]), vshuffle(_3SBOX, abcd[0]),
                       vshuffle(_1SBOX, _3abcd[3]), vshuffle(_1SBOX, abcd[2]));
    e[5] = vxor4values(vshuffle(_1SBOX, _3abcd[1]), vshuffle(_2SBOX, abcd[0]),
                       vshuffle(_3SBOX, _3abcd[3]), vshuffle(_1SBOX, abcd[2]));
    e[6] = vxor4values(vshuffle(_1SBOX, _3abcd[1]), vshuffle(_1SBOX, abcd[0]),
                       vshuffle(_2SBOX, _3abcd[3]), vshuffle(_3SBOX, abcd[2]));
    e[7] = vxor4values(vshuffle(_3SBOX, _3abcd[1]), vshuffle(_1SBOX, abcd[0]),
                       vshuffle(_1SBOX, _3abcd[3]), vshuffle(_2SBOX, abcd[2]));

    e[8] = vxor4values(vshuffle(_2SBOX, _2abcd[0]), vshuffle(_3SBOX, abcd[3]),
                       vshuffle(_1SBOX, _2abcd[2]), vshuffle(_1SBOX, abcd[1]));
    e[9] = vxor4values(vshuffle(_1SBOX, _2abcd[0]), vshuffle(_2SBOX, abcd[3]),
                       vshuffle(_3SBOX, _2abcd[2]), vshuffle(_1SBOX, abcd[1]));
    e[10] = vxor4values(vshuffle(_1SBOX, _2abcd[0]), vshuffle(_1SBOX, abcd[3]),
                        vshuffle(_2SBOX, _2abcd[2]), vshuffle(_3SBOX, abcd[1]));
    e[11] = vxor4values(vshuffle(_3SBOX, _2abcd[0]), vshuffle(_1SBOX, abcd[3]),
                        vshuffle(_1SBOX, _2abcd[2]), vshuffle(_2SBOX, abcd[1]));

    e[12] = vxor4values(vshuffle(_2SBOX, abcd[3]), vshuffle(_3SBOX, _3abcd[2]),
                        vshuffle(_1SBOX, abcd[1]), vshuffle(_1SBOX, _3abcd[0]));
    e[13] = vxor4values(vshuffle(_1SBOX, abcd[3]), vshuffle(_2SBOX, _3abcd[2]),
                        vshuffle(_3SBOX, abcd[1]), vshuffle(_1SBOX, _3abcd[0]));
    e[14] = vxor4values(vshuffle(_1SBOX, abcd[3]), vshuffle(_1SBOX, _3abcd[2]),
                        vshuffle(_2SBOX, abcd[1]), vshuffle(_3SBOX, _3abcd[0]));
    e[15] = vxor4values(vshuffle(_3SBOX, abcd[3]), vshuffle(_1SBOX, _3abcd[2]),
                        vshuffle(_1SBOX, abcd[1]), vshuffle(_2SBOX, _3abcd[0]));
}

// ---------------------------------------------------------

static void finalize_config3(__m128i abcd[4],
                             __m128i _2abcd[4],
                             __m128i _3abcd[4],
                             __m128i e[16]) {
    e[0] = vxor4values(vshuffle(_2SBOX, _3abcd[1]), vshuffle(_3SBOX, abcd[0]),
                       vshuffle(_1SBOX, _3abcd[3]), vshuffle(_1SBOX, abcd[2]));
    e[1] = vxor4values(vshuffle(_1SBOX, _3abcd[1]), vshuffle(_2SBOX, abcd[0]),
                       vshuffle(_3SBOX, _3abcd[3]), vshuffle(_1SBOX, abcd[2]));
    e[2] = vxor4values(vshuffle(_1SBOX, _3abcd[1]), vshuffle(_1SBOX, abcd[0]),
                       vshuffle(_2SBOX, _3abcd[3]), vshuffle(_3SBOX, abcd[2]));
    e[3] = vxor4values(vshuffle(_3SBOX, _3abcd[1]), vshuffle(_1SBOX, abcd[0]),
                       vshuffle(_1SBOX, _3abcd[3]), vshuffle(_2SBOX, abcd[2]));

    e[4] = vxor4values(vshuffle(_2SBOX, _2abcd[0]), vshuffle(_3SBOX, abcd[3]),
                       vshuffle(_1SBOX, _2abcd[2]), vshuffle(_1SBOX, abcd[1]));
    e[5] = vxor4values(vshuffle(_1SBOX, _2abcd[0]), vshuffle(_2SBOX, abcd[3]),
                       vshuffle(_3SBOX, _2abcd[2]), vshuffle(_1SBOX, abcd[1]));
    e[6] = vxor4values(vshuffle(_1SBOX, _2abcd[0]), vshuffle(_1SBOX, abcd[3]),
                       vshuffle(_2SBOX, _2abcd[2]), vshuffle(_3SBOX, abcd[1]));
    e[7] = vxor4values(vshuffle(_3SBOX, _2abcd[0]), vshuffle(_1SBOX, abcd[3]),
                       vshuffle(_1SBOX, _2abcd[2]), vshuffle(_2SBOX, abcd[1]));

    e[8] = vxor4values(vshuffle(_2SBOX, abcd[3]), vshuffle(_3SBOX, _3abcd[2]),
                       vshuffle(_1SBOX, abcd[1]), vshuffle(_1SBOX, _3abcd[0]));
    e[9] = vxor4values(vshuffle(_1SBOX, abcd[3]), vshuffle(_2SBOX, _3abcd[2]),
                       vshuffle(_3SBOX, abcd[1]), vshuffle(_1SBOX, _3abcd[0]));
    e[10] = vxor4values(vshuffle(_1SBOX, abcd[3]), vshuffle(_1SBOX, _3abcd[2]),
                        vshuffle(_2SBOX, abcd[1]), vshuffle(_3SBOX, _3abcd[0]));
    e[11] = vxor4values(vshuffle(_3SBOX, abcd[3]), vshuffle(_1SBOX, _3abcd[2]),
                        vshuffle(_1SBOX, abcd[1]), vshuffle(_2SBOX, _3abcd[0]));

    e[12] = vxor4values(vshuffle(_2SBOX, abcd[2]), vshuffle(_3SBOX, _2abcd[1]),
                        vshuffle(_1SBOX, abcd[0]), vshuffle(_1SBOX, _2abcd[3]));
    e[13] = vxor4values(vshuffle(_1SBOX, abcd[2]), vshuffle(_2SBOX, _2abcd[1]),
                        vshuffle(_3SBOX, abcd[0]), vshuffle(_1SBOX, _2abcd[3]));
    e[14] = vxor4values(vshuffle(_1SBOX, abcd[2]), vshuffle(_1SBOX, _2abcd[1]),
                        vshuffle(_2SBOX, abcd[0]), vshuffle(_3SBOX, _2abcd[3]));
    e[15] = vxor4values(vshuffle(_3SBOX, abcd[2]), vshuffle(_1SBOX, _2abcd[1]),
                        vshuffle(_1SBOX, abcd[0]), vshuffle(_2SBOX, _2abcd[3]));
}

// ---------------------------------------------------------

static void finalize_config(const size_t config_index,
                            __m128i abcd[4],
                            __m128i _2abcd[4],
                            __m128i _3abcd[4],
                            __m128i e[16]) {
    if (config_index == 0) {
        finalize_config0(abcd, _2abcd, _3abcd, e);
    } else if (config_index == 1) {
        finalize_config1(abcd, _2abcd, _3abcd, e);
    } else if (config_index == 2) {
        finalize_config2(abcd, _2abcd, _3abcd, e);
    } else if (config_index == 3) {
        finalize_config3(abcd, _2abcd, _3abcd, e);
    }
}

// ---------------------------------------------------------

/**
 * Assumes __m128i inout[4], __m128i k[4] and computes
 * inout[i] ^= k[i] for all i.
 */
#define vxor_arrays_four(inout, k) do {\
    inout[0] = vxor(inout[0], k[0]); \
    inout[1] = vxor(inout[1], k[1]); \
    inout[2] = vxor(inout[2], k[2]); \
    inout[3] = vxor(inout[3], k[3]); \
} while (0)

// ---------------------------------------------------------

/**
 * Assumes __m128i out[4], __m128i in[4], __m128i sbox and computes
 * out[i] = sbox(in[i]) for all i.
 */
#define vshuffle_arrays_four(out, in, sbox) do {\
    out[0] = vshuffle(sbox, in[0]); \
    out[1] = vshuffle(sbox, in[1]); \
    out[2] = vshuffle(sbox, in[2]); \
    out[3] = vshuffle(sbox, in[3]); \
} while (0)

// ---------------------------------------------------------

static void prepare_multiples(__m128i abcd[4],
                              __m128i _2abcd[4],
                              __m128i _3abcd[4],
                              __m128i k2[4]) {
    vshuffle_arrays_four(_2abcd, abcd, _X2);
    vshuffle_arrays_four(_3abcd, abcd, _X3);

    vxor_arrays_four(abcd, k2);
    vxor_arrays_four(_2abcd, k2);
    vxor_arrays_four(_3abcd, k2);
}

// ---------------------------------------------------------

static void
compute_input_variables0(__m128i x, __m128i abcd[4], __m128i k1[4]) {
    abcd[0] = vshuffle(_1SBOX, vxor(vshuffle(_X2, x), k1[0]));
    abcd[1] = vshuffle(_1SBOX, vxor(x, k1[1]));
    abcd[2] = vshuffle(_1SBOX, vxor(x, k1[2]));
    abcd[3] = vshuffle(_1SBOX, vxor(vshuffle(_X3, x), k1[3]));
}

// ---------------------------------------------------------

static void
compute_input_variables1(__m128i x, __m128i abcd[4], __m128i k1[4]) {
    abcd[0] = vshuffle(_1SBOX, vxor(vshuffle(_X3, x), k1[0]));
    abcd[1] = vshuffle(_1SBOX, vxor(vshuffle(_X2, x), k1[1]));
    abcd[2] = vshuffle(_1SBOX, vxor(x, k1[2]));
    abcd[3] = vshuffle(_1SBOX, vxor(x, k1[3]));
}

// ---------------------------------------------------------

static void
compute_input_variables2(__m128i x, __m128i abcd[4], __m128i k1[4]) {
    abcd[0] = vshuffle(_1SBOX, vxor(x, k1[0]));
    abcd[1] = vshuffle(_1SBOX, vxor(vshuffle(_X3, x), k1[1]));
    abcd[2] = vshuffle(_1SBOX, vxor(vshuffle(_X2, x), k1[2]));
    abcd[3] = vshuffle(_1SBOX, vxor(x, k1[3]));
}

// ---------------------------------------------------------

static void
compute_input_variables3(__m128i x, __m128i abcd[4], __m128i k1[4]) {
    abcd[0] = vshuffle(_1SBOX, vxor(x, k1[0]));
    abcd[1] = vshuffle(_1SBOX, vxor(x, k1[1]));
    abcd[2] = vshuffle(_1SBOX, vxor(vshuffle(_X3, x), k1[2]));
    abcd[3] = vshuffle(_1SBOX, vxor(vshuffle(_X2, x), k1[3]));
}

// ---------------------------------------------------------

/**
 * Calls the compute_input_variable<r> depending on the row_index r.
 */
static void
compute_input_variables(const size_t row_index,
                        __m128i x, __m128i abcd[4], __m128i k1[4]) {
    if (row_index == 0) {
        compute_input_variables0(x, abcd, k1);
    } else if (row_index == 1) {
        compute_input_variables1(x, abcd, k1);
    } else if (row_index == 2) {
        compute_input_variables2(x, abcd, k1);
    } else if (row_index == 3) {
        compute_input_variables3(x, abcd, k1);
    }
}

// ---------------------------------------------------------

static void prepare_key(__m128i k[4], size_t index) {
    for (size_t i = 0; i < 4; ++i) {
        k[i] = vset8_single(index & 0x0F);
        index >>= 4;
    }
}

// ---------------------------------------------------------
// Experiment functions
// ---------------------------------------------------------

/**
 * Finds number of unordered collisions among any two bytes in x.
 * @param x
 * @return
 */
static size_t
find_collisions(uint8_t list[16], uint8_t histogram[16], const __m128i x) {
    memset(list, 0x00, 16);
    storeu(list, x);
    memset(histogram, 0x00, 16);

    for (size_t i = 0; i < 16; ++i) {
        histogram[list[i] & 0x0F]++;
    }

    size_t num_collisions = 0;

    for (size_t i = 0; i < 16; ++i) {
        num_collisions += (histogram[i] * (histogram[i] - 1)) / 2;
    }

    return num_collisions;
}

// ---------------------------------------------------------

static void perform_experiments(ExperimentContext &context) {
    const __m128i x = vsetr8(0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
                             0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf);
    __m128i abcd[4];
    __m128i _2abcd[4];
    __m128i _3abcd[4];

    __m128i result[16];
    __m128i k1[4];
    __m128i k2[4];

    const size_t num_keys = 1L << 16;
    uint8_t list[16];
    uint8_t histogram[16];

    std::cout << "# in out num_collisions" << std::endl;

    for (size_t input_index = 0; input_index < 16; ++input_index) {
        const size_t row_index = input_index % 4;
        const size_t column_index = input_index / 4;
        const size_t config_index = (4 + row_index - column_index) % 4;

        printf("# in %2zu\n", input_index);

        size_t num_collisions[16] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

        for (size_t k1_value = 0; k1_value < num_keys; ++k1_value) {
            prepare_key(k1, k1_value);

            for (size_t k2_value = 0; k2_value < num_keys; ++k2_value) {
                prepare_key(k2, k2_value);
                compute_input_variables(row_index, x, abcd, k1);
                prepare_multiples(abcd, _2abcd, _3abcd, k2);

                finalize_config(config_index, abcd, _2abcd, _3abcd, result);

                for (size_t output_index = 0;
                     output_index < 16;
                     ++output_index) {
                    num_collisions[output_index] += find_collisions(
                        list, histogram, result[output_index]
                    );
                }
            }

            if ((k1_value > 0) && ((k1_value & 0x00FF) == 0)) {
                printf("# %6zu / %6zu \n", k1_value, num_keys);
            }
        }

        for (size_t output_index = 0; output_index < 16; ++output_index) {
            printf("%2zu %2zu %8zu\n", input_index, output_index,
                   num_collisions[output_index]);
        }
    }
}

// ---------------------------------------------------------

static void perform_test_experiment(ExperimentContext &context) {
    const __m128i x = vsetr8(0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
                             0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf);
    __m128i abcd[4];
    __m128i _2abcd[4];
    __m128i _3abcd[4];

    __m128i result[16];
    __m128i k1[4];
    __m128i k2[4];

    uint8_t list[16];
    uint8_t histogram[16];

    std::cout << "# in out num_collisions" << std::endl;

    const size_t input_index = 0;

    const size_t row_index = input_index % 4;
    const size_t column_index = input_index / 4;
    const size_t config_index = (4 + row_index - column_index) % 4;

    printf("# in %2zu row %2zu col %2zu config %2zu\n",
        input_index, row_index, column_index, config_index);

    size_t num_collisions[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    const size_t k1_value = 0x4321;
    prepare_key(k1, k1_value);

    const size_t k2_value = 0xEFEF;
    prepare_key(k2, k2_value);

    utils::print_128("K1", k1[0]);
    utils::print_128("K1", k1[1]);
    utils::print_128("K1", k1[2]);
    utils::print_128("K1", k1[3]);
    utils::print_128("K2", k2[0]);
    utils::print_128("K2", k2[1]);
    utils::print_128("K2", k2[2]);
    utils::print_128("K2", k2[3]);

    compute_input_variables(row_index, x, abcd, k1);

    utils::print_128("x ", x);

    utils::print_128(" a", abcd[0]);
    utils::print_128(" b", abcd[1]);
    utils::print_128(" c", abcd[2]);
    utils::print_128(" d", abcd[3]);

    prepare_multiples(abcd, _2abcd, _3abcd, k2);

    utils::print_128(" a + k2[0]", abcd[0]);
    utils::print_128(" b + k2[1]", abcd[1]);
    utils::print_128(" c + k2[2]", abcd[2]);
    utils::print_128(" d + k2[3]", abcd[3]);

    utils::print_128("2a + k2[0]", _2abcd[0]);
    utils::print_128("2b + k2[1]", _2abcd[1]);
    utils::print_128("2c + k2[2]", _2abcd[2]);
    utils::print_128("2d + k2[3]", _2abcd[3]);

    utils::print_128("3a + k2[0]", _3abcd[0]);
    utils::print_128("3b + k2[1]", _3abcd[1]);
    utils::print_128("3c + k2[2]", _3abcd[2]);
    utils::print_128("3d + k2[3]", _3abcd[3]);

    finalize_config(config_index, abcd, _2abcd, _3abcd, result);

    const size_t output_index = 0;
    num_collisions[output_index] += find_collisions(
        list, histogram, result[output_index]
    );

    utils::print_128("Result: ", result[output_index]);
    utils::print_hex("List   ", list, 16);

    printf("%2zu %2zu %8zu\n", input_index, output_index,
        num_collisions[output_index]);
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static void parse_args(ExperimentContext *context,
                       int argc,
                       const char **argv) {
    ArgumentParser parser;
    parser.appName(
        "Tests the number of collisions for all possible inputs to the "
        "Small-AES cell-to-cell four-round distinguisher.");

    try {
        parser.parse((size_t) argc, argv);
    } catch (...) {
        std::cerr << parser.usage() << std::endl;
        exit(EXIT_FAILURE);
    }
}

// ---------------------------------------------------------

int main(int argc, const char **argv) {
    ExperimentContext context;
    parse_args(&context, argc, argv);
    perform_test_experiment(context);
    perform_experiments(context);
    return EXIT_SUCCESS;
}
