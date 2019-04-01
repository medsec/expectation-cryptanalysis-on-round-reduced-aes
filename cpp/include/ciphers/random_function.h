/**
 * __author__ = anonymous
 * __date__   = 2019-01
 * __copyright__ = CC0
 */
#ifndef _RANDOM_FUNCTION_H_
#define _RANDOM_FUNCTION_H_

// ---------------------------------------------------------

#include <stdlib.h>

#include "utils/utils.h"
#include "utils/xorshift1024.h"

// ---------------------------------------------------------

namespace ciphers {

    class RandomFunction {

    public:

        explicit RandomFunction(const size_t num_bytes) : num_bytes(num_bytes) {
            xorshift1024_init(&xorshift_prng_ctx);
        }

        void encrypt(uint8_t* ciphertext) {
            utils::get_random_bytes(&xorshift_prng_ctx, ciphertext, num_bytes);
        }

    private:

        size_t num_bytes;
        utils::xorshift_prng_ctx_t xorshift_prng_ctx;

    };

}

// ---------------------------------------------------------

#endif //_RANDOM_FUNCTION_H_
