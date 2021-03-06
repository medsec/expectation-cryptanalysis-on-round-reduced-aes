/**
 * C
 *
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */
#ifndef _AES_STATE_H_
#define _AES_STATE_H_

// ---------------------------------------------------------------------

#include "ciphers/aes.h"

// ---------------------------------------------------------------------

namespace ciphers {

    class AESState {

    public:

        AESState() {

        }

        aes_state_t state;

    };

}

// ---------------------------------------------------------------------

#endif //_AES_STATE_H_
