/**
 * C
 *
 * __author__ = anonymous
 * __date__   = 2018-05
 * __copyright__ = Creative Commons CC0
 */
#ifndef _SMALL_AES_STATE_H_
#define _SMALL_AES_STATE_H_

// ---------------------------------------------------------------------

#include "ciphers/small_aes.h"

// ---------------------------------------------------------------------

namespace ciphers {

    class SmallState {

    public:

        SmallState() {

        }

        small_aes_state_t state;

    };

}

// ---------------------------------------------------------------------

#endif //_SMALL_AES_STATE_H_
