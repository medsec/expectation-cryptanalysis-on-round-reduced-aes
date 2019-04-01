/**
 * C
 *
 * __author__ = anonymous
 * __date__   = 2018-05
 * __copyright__ = Creative Commons CC0
 */
#ifndef _SMALL_AES_STATE_PAIR_H_
#define _SMALL_AES_STATE_PAIR_H_

// ---------------------------------------------------------------------

#include "ciphers/small_aes.h"

// ---------------------------------------------------------------------

namespace ciphers {

    class SmallStatePair {

    public:

        SmallStatePair() {

        }

        small_aes_state_t first;
        small_aes_state_t second;
        bool processed = false;

    };

}

// ---------------------------------------------------------------------

#endif //_SMALL_AES_STATE_PAIR_H_
