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
#include "utils/xorshift1024.h"

using utils::ArgumentParser;

// ---------------------------------------------------------

typedef struct {
    __m128i _1SBOX;
    __m128i _2SBOX;
    __m128i _3SBOX;
} ExperimentContext;

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
static void finalize_config0(const ExperimentContext &context,
                             __m128i abcd[4],
                             __m128i _2abcd[4],
                             __m128i _3abcd[4],
                             __m128i e[16]) {
    e[0] = vxor4values(vshuffle(context._2SBOX, _2abcd[0]),
                       vshuffle(context._3SBOX, abcd[3]),
                       vshuffle(context._1SBOX, _2abcd[2]),
                       vshuffle(context._1SBOX, abcd[1]));
    e[1] = vxor4values(vshuffle(context._1SBOX, _2abcd[0]),
                       vshuffle(context._2SBOX, abcd[3]),
                       vshuffle(context._3SBOX, _2abcd[2]),
                       vshuffle(context._1SBOX, abcd[1]));
    e[2] = vxor4values(vshuffle(context._1SBOX, _2abcd[0]),
                       vshuffle(context._1SBOX, abcd[3]),
                       vshuffle(context._2SBOX, _2abcd[2]),
                       vshuffle(context._3SBOX, abcd[1]));
    e[3] = vxor4values(vshuffle(context._3SBOX, _2abcd[0]),
                       vshuffle(context._1SBOX, abcd[3]),
                       vshuffle(context._1SBOX, _2abcd[2]),
                       vshuffle(context._2SBOX, abcd[1]));

    e[4] = vxor4values(vshuffle(context._2SBOX, abcd[3]),
                       vshuffle(context._3SBOX, _3abcd[2]),
                       vshuffle(context._1SBOX, abcd[1]),
                       vshuffle(context._1SBOX, _3abcd[0]));
    e[5] = vxor4values(vshuffle(context._1SBOX, abcd[3]),
                       vshuffle(context._2SBOX, _3abcd[2]),
                       vshuffle(context._3SBOX, abcd[1]),
                       vshuffle(context._1SBOX, _3abcd[0]));
    e[6] = vxor4values(vshuffle(context._1SBOX, abcd[3]),
                       vshuffle(context._1SBOX, _3abcd[2]),
                       vshuffle(context._2SBOX, abcd[1]),
                       vshuffle(context._3SBOX, _3abcd[0]));
    e[7] = vxor4values(vshuffle(context._3SBOX, abcd[3]),
                       vshuffle(context._1SBOX, _3abcd[2]),
                       vshuffle(context._1SBOX, abcd[1]),
                       vshuffle(context._2SBOX, _3abcd[0]));

    e[8] = vxor4values(vshuffle(context._2SBOX, abcd[2]),
                       vshuffle(context._3SBOX, _2abcd[1]),
                       vshuffle(context._1SBOX, abcd[0]),
                       vshuffle(context._1SBOX, _2abcd[3]));
    e[9] = vxor4values(vshuffle(context._1SBOX, abcd[2]),
                       vshuffle(context._2SBOX, _2abcd[1]),
                       vshuffle(context._3SBOX, abcd[0]),
                       vshuffle(context._1SBOX, _2abcd[3]));
    e[10] = vxor4values(vshuffle(context._1SBOX, abcd[2]),
                        vshuffle(context._1SBOX, _2abcd[1]),
                        vshuffle(context._2SBOX, abcd[0]),
                        vshuffle(context._3SBOX, _2abcd[3]));
    e[11] = vxor4values(vshuffle(context._3SBOX, abcd[2]),
                        vshuffle(context._1SBOX, _2abcd[1]),
                        vshuffle(context._1SBOX, abcd[0]),
                        vshuffle(context._2SBOX, _2abcd[3]));

    e[12] = vxor4values(vshuffle(context._2SBOX, _3abcd[1]),
                        vshuffle(context._3SBOX, abcd[0]),
                        vshuffle(context._1SBOX, _3abcd[3]),
                        vshuffle(context._1SBOX, abcd[2]));
    e[13] = vxor4values(vshuffle(context._1SBOX, _3abcd[1]),
                        vshuffle(context._2SBOX, abcd[0]),
                        vshuffle(context._3SBOX, _3abcd[3]),
                        vshuffle(context._1SBOX, abcd[2]));
    e[14] = vxor4values(vshuffle(context._1SBOX, _3abcd[1]),
                        vshuffle(context._1SBOX, abcd[0]),
                        vshuffle(context._2SBOX, _3abcd[3]),
                        vshuffle(context._3SBOX, abcd[2]));
    e[15] = vxor4values(vshuffle(context._3SBOX, _3abcd[1]),
                        vshuffle(context._1SBOX, abcd[0]),
                        vshuffle(context._1SBOX, _3abcd[3]),
                        vshuffle(context._2SBOX, abcd[2]));
}

// ---------------------------------------------------------

static void finalize_config1(const ExperimentContext &context,
                             __m128i abcd[4],
                             __m128i _2abcd[4],
                             __m128i _3abcd[4],
                             __m128i e[16]) {
    e[0] = vxor4values(vshuffle(context._2SBOX, abcd[3]),
                       vshuffle(context._3SBOX, _3abcd[2]),
                       vshuffle(context._1SBOX, abcd[1]),
                       vshuffle(context._1SBOX, _3abcd[0]));
    e[1] = vxor4values(vshuffle(context._1SBOX, abcd[3]),
                       vshuffle(context._2SBOX, _3abcd[2]),
                       vshuffle(context._3SBOX, abcd[1]),
                       vshuffle(context._1SBOX, _3abcd[0]));
    e[2] = vxor4values(vshuffle(context._1SBOX, abcd[3]),
                       vshuffle(context._1SBOX, _3abcd[2]),
                       vshuffle(context._2SBOX, abcd[1]),
                       vshuffle(context._3SBOX, _3abcd[0]));
    e[3] = vxor4values(vshuffle(context._3SBOX, abcd[3]),
                       vshuffle(context._1SBOX, _3abcd[2]),
                       vshuffle(context._1SBOX, abcd[1]),
                       vshuffle(context._2SBOX, _3abcd[0]));

    e[4] = vxor4values(vshuffle(context._2SBOX, abcd[2]),
                       vshuffle(context._3SBOX, _2abcd[1]),
                       vshuffle(context._1SBOX, abcd[0]),
                       vshuffle(context._1SBOX, _2abcd[3]));
    e[5] = vxor4values(vshuffle(context._1SBOX, abcd[2]),
                       vshuffle(context._2SBOX, _2abcd[1]),
                       vshuffle(context._3SBOX, abcd[0]),
                       vshuffle(context._1SBOX, _2abcd[3]));
    e[6] = vxor4values(vshuffle(context._1SBOX, abcd[2]),
                       vshuffle(context._1SBOX, _2abcd[1]),
                       vshuffle(context._2SBOX, abcd[0]),
                       vshuffle(context._3SBOX, _2abcd[3]));
    e[7] = vxor4values(vshuffle(context._3SBOX, abcd[2]),
                       vshuffle(context._1SBOX, _2abcd[1]),
                       vshuffle(context._1SBOX, abcd[0]),
                       vshuffle(context._2SBOX, _2abcd[3]));

    e[8] = vxor4values(vshuffle(context._2SBOX, _3abcd[1]),
                       vshuffle(context._3SBOX, abcd[0]),
                       vshuffle(context._1SBOX, _3abcd[3]),
                       vshuffle(context._1SBOX, abcd[2]));
    e[9] = vxor4values(vshuffle(context._1SBOX, _3abcd[1]),
                       vshuffle(context._2SBOX, abcd[0]),
                       vshuffle(context._3SBOX, _3abcd[3]),
                       vshuffle(context._1SBOX, abcd[2]));
    e[10] = vxor4values(vshuffle(context._1SBOX, _3abcd[1]),
                        vshuffle(context._1SBOX, abcd[0]),
                        vshuffle(context._2SBOX, _3abcd[3]),
                        vshuffle(context._3SBOX, abcd[2]));
    e[11] = vxor4values(vshuffle(context._3SBOX, _3abcd[1]),
                        vshuffle(context._1SBOX, abcd[0]),
                        vshuffle(context._1SBOX, _3abcd[3]),
                        vshuffle(context._2SBOX, abcd[2]));

    e[12] = vxor4values(vshuffle(context._2SBOX, _2abcd[0]),
                        vshuffle(context._3SBOX, abcd[3]),
                        vshuffle(context._1SBOX, _2abcd[2]),
                        vshuffle(context._1SBOX, abcd[1]));
    e[13] = vxor4values(vshuffle(context._1SBOX, _2abcd[0]),
                        vshuffle(context._2SBOX, abcd[3]),
                        vshuffle(context._3SBOX, _2abcd[2]),
                        vshuffle(context._1SBOX, abcd[1]));
    e[14] = vxor4values(vshuffle(context._1SBOX, _2abcd[0]),
                        vshuffle(context._1SBOX, abcd[3]),
                        vshuffle(context._2SBOX, _2abcd[2]),
                        vshuffle(context._3SBOX, abcd[1]));
    e[15] = vxor4values(vshuffle(context._3SBOX, _2abcd[0]),
                        vshuffle(context._1SBOX, abcd[3]),
                        vshuffle(context._1SBOX, _2abcd[2]),
                        vshuffle(context._2SBOX, abcd[1]));
}

// ---------------------------------------------------------

static void finalize_config2(const ExperimentContext &context,
                             __m128i abcd[4],
                             __m128i _2abcd[4],
                             __m128i _3abcd[4],
                             __m128i e[16]) {
    e[0] = vxor4values(vshuffle(context._2SBOX, abcd[2]),
                       vshuffle(context._3SBOX, _2abcd[1]),
                       vshuffle(context._1SBOX, abcd[0]),
                       vshuffle(context._1SBOX, _2abcd[3]));
    e[1] = vxor4values(vshuffle(context._1SBOX, abcd[2]),
                       vshuffle(context._2SBOX, _2abcd[1]),
                       vshuffle(context._3SBOX, abcd[0]),
                       vshuffle(context._1SBOX, _2abcd[3]));
    e[2] = vxor4values(vshuffle(context._1SBOX, abcd[2]),
                       vshuffle(context._1SBOX, _2abcd[1]),
                       vshuffle(context._2SBOX, abcd[0]),
                       vshuffle(context._3SBOX, _2abcd[3]));
    e[3] = vxor4values(vshuffle(context._3SBOX, abcd[2]),
                       vshuffle(context._1SBOX, _2abcd[1]),
                       vshuffle(context._1SBOX, abcd[0]),
                       vshuffle(context._2SBOX, _2abcd[3]));

    e[4] = vxor4values(vshuffle(context._2SBOX, _3abcd[1]),
                       vshuffle(context._3SBOX, abcd[0]),
                       vshuffle(context._1SBOX, _3abcd[3]),
                       vshuffle(context._1SBOX, abcd[2]));
    e[5] = vxor4values(vshuffle(context._1SBOX, _3abcd[1]),
                       vshuffle(context._2SBOX, abcd[0]),
                       vshuffle(context._3SBOX, _3abcd[3]),
                       vshuffle(context._1SBOX, abcd[2]));
    e[6] = vxor4values(vshuffle(context._1SBOX, _3abcd[1]),
                       vshuffle(context._1SBOX, abcd[0]),
                       vshuffle(context._2SBOX, _3abcd[3]),
                       vshuffle(context._3SBOX, abcd[2]));
    e[7] = vxor4values(vshuffle(context._3SBOX, _3abcd[1]),
                       vshuffle(context._1SBOX, abcd[0]),
                       vshuffle(context._1SBOX, _3abcd[3]),
                       vshuffle(context._2SBOX, abcd[2]));

    e[8] = vxor4values(vshuffle(context._2SBOX, _2abcd[0]),
                       vshuffle(context._3SBOX, abcd[3]),
                       vshuffle(context._1SBOX, _2abcd[2]),
                       vshuffle(context._1SBOX, abcd[1]));
    e[9] = vxor4values(vshuffle(context._1SBOX, _2abcd[0]),
                       vshuffle(context._2SBOX, abcd[3]),
                       vshuffle(context._3SBOX, _2abcd[2]),
                       vshuffle(context._1SBOX, abcd[1]));
    e[10] = vxor4values(vshuffle(context._1SBOX, _2abcd[0]),
                        vshuffle(context._1SBOX, abcd[3]),
                        vshuffle(context._2SBOX, _2abcd[2]),
                        vshuffle(context._3SBOX, abcd[1]));
    e[11] = vxor4values(vshuffle(context._3SBOX, _2abcd[0]),
                        vshuffle(context._1SBOX, abcd[3]),
                        vshuffle(context._1SBOX, _2abcd[2]),
                        vshuffle(context._2SBOX, abcd[1]));

    e[12] = vxor4values(vshuffle(context._2SBOX, abcd[3]),
                        vshuffle(context._3SBOX, _3abcd[2]),
                        vshuffle(context._1SBOX, abcd[1]),
                        vshuffle(context._1SBOX, _3abcd[0]));
    e[13] = vxor4values(vshuffle(context._1SBOX, abcd[3]),
                        vshuffle(context._2SBOX, _3abcd[2]),
                        vshuffle(context._3SBOX, abcd[1]),
                        vshuffle(context._1SBOX, _3abcd[0]));
    e[14] = vxor4values(vshuffle(context._1SBOX, abcd[3]),
                        vshuffle(context._1SBOX, _3abcd[2]),
                        vshuffle(context._2SBOX, abcd[1]),
                        vshuffle(context._3SBOX, _3abcd[0]));
    e[15] = vxor4values(vshuffle(context._3SBOX, abcd[3]),
                        vshuffle(context._1SBOX, _3abcd[2]),
                        vshuffle(context._1SBOX, abcd[1]),
                        vshuffle(context._2SBOX, _3abcd[0]));
}

// ---------------------------------------------------------

static void finalize_config3(const ExperimentContext &context,
                             __m128i abcd[4],
                             __m128i _2abcd[4],
                             __m128i _3abcd[4],
                             __m128i e[16]) {
    e[0] = vxor4values(vshuffle(context._2SBOX, _3abcd[1]),
                       vshuffle(context._3SBOX, abcd[0]),
                       vshuffle(context._1SBOX, _3abcd[3]),
                       vshuffle(context._1SBOX, abcd[2]));
    e[1] = vxor4values(vshuffle(context._1SBOX, _3abcd[1]),
                       vshuffle(context._2SBOX, abcd[0]),
                       vshuffle(context._3SBOX, _3abcd[3]),
                       vshuffle(context._1SBOX, abcd[2]));
    e[2] = vxor4values(vshuffle(context._1SBOX, _3abcd[1]),
                       vshuffle(context._1SBOX, abcd[0]),
                       vshuffle(context._2SBOX, _3abcd[3]),
                       vshuffle(context._3SBOX, abcd[2]));
    e[3] = vxor4values(vshuffle(context._3SBOX, _3abcd[1]),
                       vshuffle(context._1SBOX, abcd[0]),
                       vshuffle(context._1SBOX, _3abcd[3]),
                       vshuffle(context._2SBOX, abcd[2]));

    e[4] = vxor4values(vshuffle(context._2SBOX, _2abcd[0]),
                       vshuffle(context._3SBOX, abcd[3]),
                       vshuffle(context._1SBOX, _2abcd[2]),
                       vshuffle(context._1SBOX, abcd[1]));
    e[5] = vxor4values(vshuffle(context._1SBOX, _2abcd[0]),
                       vshuffle(context._2SBOX, abcd[3]),
                       vshuffle(context._3SBOX, _2abcd[2]),
                       vshuffle(context._1SBOX, abcd[1]));
    e[6] = vxor4values(vshuffle(context._1SBOX, _2abcd[0]),
                       vshuffle(context._1SBOX, abcd[3]),
                       vshuffle(context._2SBOX, _2abcd[2]),
                       vshuffle(context._3SBOX, abcd[1]));
    e[7] = vxor4values(vshuffle(context._3SBOX, _2abcd[0]),
                       vshuffle(context._1SBOX, abcd[3]),
                       vshuffle(context._1SBOX, _2abcd[2]),
                       vshuffle(context._2SBOX, abcd[1]));

    e[8] = vxor4values(vshuffle(context._2SBOX, abcd[3]),
                       vshuffle(context._3SBOX, _3abcd[2]),
                       vshuffle(context._1SBOX, abcd[1]),
                       vshuffle(context._1SBOX, _3abcd[0]));
    e[9] = vxor4values(vshuffle(context._1SBOX, abcd[3]),
                       vshuffle(context._2SBOX, _3abcd[2]),
                       vshuffle(context._3SBOX, abcd[1]),
                       vshuffle(context._1SBOX, _3abcd[0]));
    e[10] = vxor4values(vshuffle(context._1SBOX, abcd[3]),
                        vshuffle(context._1SBOX, _3abcd[2]),
                        vshuffle(context._2SBOX, abcd[1]),
                        vshuffle(context._3SBOX, _3abcd[0]));
    e[11] = vxor4values(vshuffle(context._3SBOX, abcd[3]),
                        vshuffle(context._1SBOX, _3abcd[2]),
                        vshuffle(context._1SBOX, abcd[1]),
                        vshuffle(context._2SBOX, _3abcd[0]));

    e[12] = vxor4values(vshuffle(context._2SBOX, abcd[2]),
                        vshuffle(context._3SBOX, _2abcd[1]),
                        vshuffle(context._1SBOX, abcd[0]),
                        vshuffle(context._1SBOX, _2abcd[3]));
    e[13] = vxor4values(vshuffle(context._1SBOX, abcd[2]),
                        vshuffle(context._2SBOX, _2abcd[1]),
                        vshuffle(context._3SBOX, abcd[0]),
                        vshuffle(context._1SBOX, _2abcd[3]));
    e[14] = vxor4values(vshuffle(context._1SBOX, abcd[2]),
                        vshuffle(context._1SBOX, _2abcd[1]),
                        vshuffle(context._2SBOX, abcd[0]),
                        vshuffle(context._3SBOX, _2abcd[3]));
    e[15] = vxor4values(vshuffle(context._3SBOX, abcd[2]),
                        vshuffle(context._1SBOX, _2abcd[1]),
                        vshuffle(context._1SBOX, abcd[0]),
                        vshuffle(context._2SBOX, _2abcd[3]));
}

// ---------------------------------------------------------

static void finalize_config(const ExperimentContext &context,
                            const size_t config_index,
                            __m128i abcd[4],
                            __m128i _2abcd[4],
                            __m128i _3abcd[4],
                            __m128i e[16]) {
    if (config_index == 0) {
        finalize_config0(context, abcd, _2abcd, _3abcd, e);
    } else if (config_index == 1) {
        finalize_config1(context, abcd, _2abcd, _3abcd, e);
    } else if (config_index == 2) {
        finalize_config2(context, abcd, _2abcd, _3abcd, e);
    } else if (config_index == 3) {
        finalize_config3(context, abcd, _2abcd, _3abcd, e);
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
compute_input_variables0(const ExperimentContext &context,
                         __m128i x, __m128i abcd[4], __m128i k1[4]) {
    abcd[0] = vshuffle(context._1SBOX, vxor(vshuffle(_X2, x), k1[0]));
    abcd[1] = vshuffle(context._1SBOX, vxor(x, k1[1]));
    abcd[2] = vshuffle(context._1SBOX, vxor(x, k1[2]));
    abcd[3] = vshuffle(context._1SBOX, vxor(vshuffle(_X3, x), k1[3]));
}

// ---------------------------------------------------------

static void
compute_input_variables1(const ExperimentContext &context,
                         __m128i x, __m128i abcd[4], __m128i k1[4]) {
    abcd[0] = vshuffle(context._1SBOX, vxor(vshuffle(_X3, x), k1[0]));
    abcd[1] = vshuffle(context._1SBOX, vxor(vshuffle(_X2, x), k1[1]));
    abcd[2] = vshuffle(context._1SBOX, vxor(x, k1[2]));
    abcd[3] = vshuffle(context._1SBOX, vxor(x, k1[3]));
}

// ---------------------------------------------------------

static void
compute_input_variables2(const ExperimentContext &context,
                         __m128i x, __m128i abcd[4], __m128i k1[4]) {
    abcd[0] = vshuffle(context._1SBOX, vxor(x, k1[0]));
    abcd[1] = vshuffle(context._1SBOX, vxor(vshuffle(_X3, x), k1[1]));
    abcd[2] = vshuffle(context._1SBOX, vxor(vshuffle(_X2, x), k1[2]));
    abcd[3] = vshuffle(context._1SBOX, vxor(x, k1[3]));
}

// ---------------------------------------------------------

static void
compute_input_variables3(const ExperimentContext &context,
                         __m128i x, __m128i abcd[4], __m128i k1[4]) {
    abcd[0] = vshuffle(context._1SBOX, vxor(x, k1[0]));
    abcd[1] = vshuffle(context._1SBOX, vxor(x, k1[1]));
    abcd[2] = vshuffle(context._1SBOX, vxor(vshuffle(_X3, x), k1[2]));
    abcd[3] = vshuffle(context._1SBOX, vxor(vshuffle(_X2, x), k1[3]));
}

// ---------------------------------------------------------

/**
 * Calls the compute_input_variable<r> depending on the row_index r.
 */
static void
compute_input_variables(const ExperimentContext &context,
                        const size_t row_index,
                        __m128i x, __m128i abcd[4], __m128i k1[4]) {
    if (row_index == 0) {
        compute_input_variables0(context, x, abcd, k1);
    } else if (row_index == 1) {
        compute_input_variables1(context, x, abcd, k1);
    } else if (row_index == 2) {
        compute_input_variables2(context, x, abcd, k1);
    } else if (row_index == 3) {
        compute_input_variables3(context, x, abcd, k1);
    }
}

// ---------------------------------------------------------

static void prepare_key(__m128i k[4], size_t index) {
    for (size_t i = 0; i < 4; ++i) {
        k[i] = vset8_single(static_cast<char>(index & 0x0F));
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
                compute_input_variables(context, row_index, x, abcd, k1);
                prepare_multiples(abcd, _2abcd, _3abcd, k2);

                finalize_config(context, config_index, abcd, _2abcd, _3abcd,
                                result);

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

    size_t num_collisions[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0};

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

    compute_input_variables(context, row_index, x, abcd, k1);

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

    finalize_config(context, config_index, abcd, _2abcd, _3abcd, result);

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

static __m128i get_sbox(const size_t cipher_index) {
    switch (cipher_index) {
        case 0: return SMALL_AES_SBOX_1;

        case 1: return SMALL_AES_PRESENT_SBOX;
        case 2: return SMALL_AES_PRIDE_SBOX;
        case 3: return SMALL_AES_PRINCE_SBOX;
        case 4: return SMALL_AES_TOY6_SBOX;
        case 5: return SMALL_AES_TOY8_SBOX;
        case 6: return SMALL_AES_TOY10_SBOX;

        case 7: return SMALL_AES_RANDOM_SBOX0;
        case 8: return SMALL_AES_RANDOM_SBOX1;
        case 9: return SMALL_AES_RANDOM_SBOX2;
        case 10: return SMALL_AES_RANDOM_SBOX3;
        case 11: return SMALL_AES_RANDOM_SBOX4;

        case 12: return SMALL_AES_RANDOM_SBOX5;
        case 13: return SMALL_AES_RANDOM_SBOX6;
        case 14: return SMALL_AES_RANDOM_SBOX7;
        case 15: return SMALL_AES_RANDOM_SBOX8;
        case 16: return SMALL_AES_RANDOM_SBOX9;

        case 17: return SMALL_AES_RANDOM_SBOX10;
        case 18: return SMALL_AES_RANDOM_SBOX11;
        case 19: return SMALL_AES_RANDOM_SBOX12;
        case 20: return SMALL_AES_RANDOM_SBOX13;
        case 21: return SMALL_AES_RANDOM_SBOX14;

        case 22: return SMALL_AES_RANDOM_SBOX15;
        case 23: return SMALL_AES_RANDOM_SBOX16;
        case 24: return SMALL_AES_RANDOM_SBOX17;
        case 25: return SMALL_AES_RANDOM_SBOX18;
        case 26: return SMALL_AES_RANDOM_SBOX19;

        case 27: return _IDENTITY_SBOX;

        case 28: return _4_BIT_OPTIMAL_SBOX_0;
        case 29: return _4_BIT_OPTIMAL_SBOX_1;
        case 30: return _4_BIT_OPTIMAL_SBOX_2;
        case 31: return _4_BIT_OPTIMAL_SBOX_3;
        case 32: return _4_BIT_OPTIMAL_SBOX_4;
        case 33: return _4_BIT_OPTIMAL_SBOX_5;
        case 34: return _4_BIT_OPTIMAL_SBOX_6;
        case 35: return _4_BIT_OPTIMAL_SBOX_7;
        case 36: return _4_BIT_OPTIMAL_SBOX_8;
        case 37: return _4_BIT_OPTIMAL_SBOX_9;
        case 38: return _4_BIT_OPTIMAL_SBOX_10;
        case 39: return _4_BIT_OPTIMAL_SBOX_11;
        case 40: return _4_BIT_OPTIMAL_SBOX_12;
        case 41: return _4_BIT_OPTIMAL_SBOX_13;
        case 42: return _4_BIT_OPTIMAL_SBOX_14;
        case 43: return _4_BIT_OPTIMAL_SBOX_15;

        case 44: return _4_BIT_PLATINUM_SBOX_0_4_NUM_1_DL_CATEGORY_0;
        case 45: return _4_BIT_PLATINUM_SBOX_0_4_NUM_1_DL_CATEGORY_1;
        case 46: return _4_BIT_PLATINUM_SBOX_1_3_NUM_1_DL_CATEGORY_0;
        case 47: return _4_BIT_PLATINUM_SBOX_1_3_NUM_1_DL_CATEGORY_1;
        case 48: return _4_BIT_PLATINUM_SBOX_1_3_NUM_1_DL_CATEGORY_2;
        case 49: return _4_BIT_PLATINUM_SBOX_1_3_NUM_1_DL_CATEGORY_3;
        case 50: return _4_BIT_PLATINUM_SBOX_2_2_NUM_1_DL_CATEGORY_0;
        case 51: return _4_BIT_PLATINUM_SBOX_2_2_NUM_1_DL_CATEGORY_1;
        case 52: return _4_BIT_PLATINUM_SBOX_2_2_NUM_1_DL_CATEGORY_2;
        case 53: return _4_BIT_PLATINUM_SBOX_2_2_NUM_1_DL_CATEGORY_3;
        default: exit(EXIT_FAILURE);
    }
}

// ---------------------------------------------------------

static void initialize_context(ExperimentContext *context,
    const size_t cipher_index) {
    context->_1SBOX = vshuffle(_X1, get_sbox(cipher_index));
    context->_2SBOX = vshuffle(_X2, context->_1SBOX);
    context->_3SBOX = vshuffle(_X3, context->_1SBOX);
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
        "Small-AES cell-to-cell four-round distinguisher. "
        "Cipher must be {0, ..., 53} for Small-AES with one of the following S-boxes (in that order):"
        "[Small-AES, PRESENT, PRIDE, PRINCE, TOY6, TOY8, TOY10, RANDOM0, ..., RANDOM19, Identity,"
        " Optimal0, ..., Optimal15, Platinum0, ..., Platinum9]");
    parser.addArgument("-c", "--cipher", 1, false);

    try {
        parser.parse((size_t) argc, argv);

        const size_t cipher_index = parser.retrieveAsLong("c");

        if (cipher_index > 53) {
            std::cerr << "Cipher index must be in {0, ..., 53}." << std::endl;
            exit(EXIT_FAILURE);
        } else {
            initialize_context(context, cipher_index);
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
    perform_test_experiment(context);
    perform_experiments(context);
    return EXIT_SUCCESS;
}
