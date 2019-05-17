/**
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#include <stdint.h>
#include <gtest/gtest.h>

#include "ciphers/speck64.h"
#include "utils/utils.h"


using ciphers::speck64_context_t;
using ciphers::speck64_96_key_t;
using ciphers::speck64_state_t;
using utils::assert_equal;

// ---------------------------------------------------------

static void run_encryption_test(const speck64_96_key_t key,
                                const speck64_state_t plaintext,
                                const speck64_state_t expected_ciphertext) {
    speck64_context_t ctx;
    speck64_96_key_schedule(&ctx, key);

    speck64_state_t ciphertext;
    speck64_encrypt(&ctx, plaintext, ciphertext);
    ASSERT_TRUE(assert_equal(expected_ciphertext, ciphertext,
        (size_t)SPECK_64_NUM_STATE_BYTES));
}

// ---------------------------------------------------------

static void run_decryption_test(const speck64_96_key_t key,
                                const speck64_state_t ciphertext,
                                const speck64_state_t expected_plaintext) {
    speck64_context_t ctx;
    speck64_96_key_schedule(&ctx, key);

    speck64_state_t plaintext;
    speck64_decrypt(&ctx, ciphertext, plaintext);
    ASSERT_TRUE(assert_equal(expected_plaintext, plaintext,
        (size_t)SPECK_64_NUM_STATE_BYTES));
}

// ---------------------------------------------------------

TEST(Speck64_96, test_encrypt_full) {
    const speck64_96_key_t key = {
        0x13, 0x12, 0x11, 0x10, 0x0b, 0x0a, 0x09, 0x08, 0x03, 0x02, 0x01, 0x00
    };
    const speck64_state_t plaintext = {
        0x74, 0x61, 0x46, 0x20, 0x73, 0x6e, 0x61, 0x65
    };
    const speck64_state_t expected_ciphertext = {
        0x9f, 0x79, 0x52, 0xec, 0x41, 0x75, 0x94, 0x6c
    };
    run_encryption_test(key, plaintext, expected_ciphertext);
}

// ---------------------------------------------------------

TEST(Speck64_96, test_decrypt_full) {
    const speck64_96_key_t key = {
        0x13, 0x12, 0x11, 0x10, 0x0b, 0x0a, 0x09, 0x08, 0x03, 0x02, 0x01, 0x00
    };
    const speck64_state_t ciphertext = {
        0x9f, 0x79, 0x52, 0xec, 0x41, 0x75, 0x94, 0x6c
    };
    const speck64_state_t expected_plaintext = {
        0x74, 0x61, 0x46, 0x20, 0x73, 0x6e, 0x61, 0x65
    };
    run_decryption_test(key, ciphertext, expected_plaintext);
}

// ---------------------------------------------------------

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
