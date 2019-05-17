/**
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#include <stdint.h>
#include <gtest/gtest.h>

#include "ciphers/mini_aes.h"
#include "utils/utils.h"


using ciphers::mini_aes_ctx_t;
using ciphers::mini_aes_state_t;
using ciphers::mini_aes_key_t;
using utils::assert_equal;

// ---------------------------------------------------------

static void run_encryption_test(const mini_aes_key_t key,
                                const mini_aes_state_t plaintext,
                                const mini_aes_state_t expected_ciphertext) {
    mini_aes_ctx_t ctx;
    mini_aes_key_setup(&ctx, key);

    mini_aes_state_t ciphertext;
    mini_aes_encrypt(&ctx, plaintext, ciphertext);
    ASSERT_TRUE(assert_equal(expected_ciphertext, ciphertext,
                             (size_t) MINI_AES_NUM_STATE_BYTES));
}

// ---------------------------------------------------------

TEST(Mini_AES, test_encrypt_full) {
    const mini_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab
    };
    const mini_aes_state_t plaintext = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab
    };
    const mini_aes_state_t expected_ciphertext = {
        0x2b, 0x44, 0x43, 0x93, 0x8a, 0xf0
    };
    run_encryption_test(key, plaintext, expected_ciphertext);
}

// ---------------------------------------------------------

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// ---------------------------------------------------------
