/**
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#include <stdint.h>
#include <gtest/gtest.h>

#include "ciphers/aes.h"
#include "utils/utils.h"


using ciphers::aes128_ctx_t;
using ciphers::aes128_key_t;
using ciphers::aes_state_t;
using utils::assert_equal;

// ---------------------------------------------------------

static void run_encryption_test(const aes128_key_t key,
                                const aes_state_t plaintext,
                                const aes_state_t expected_ciphertext) {
    aes128_ctx_t ctx;
    aes128_key_setup(&ctx, key);
    
    aes_state_t ciphertext;
    aes128_encrypt(&ctx, plaintext, ciphertext);
    ASSERT_TRUE(assert_equal(expected_ciphertext, ciphertext, (size_t)AES_NUM_STATE_BYTES));
}

// ---------------------------------------------------------

static void run_decryption_test(const aes128_key_t key,
                                const aes_state_t ciphertext,
                                const aes_state_t expected_plaintext) {
    aes128_ctx_t ctx;
    aes128_key_setup(&ctx, key);
    
    aes_state_t plaintext;
    aes128_decrypt(&ctx, ciphertext, plaintext);
    ASSERT_TRUE(assert_equal(expected_plaintext, plaintext, (size_t)AES_NUM_STATE_BYTES));
}

// ---------------------------------------------------------

TEST(AES128, test_key_schedule) {
    const aes128_key_t key = { 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    aes128_ctx_t ctx;
    aes128_key_setup(&ctx, key);

    uint8_t round_key[AES_128_NUM_KEY_BYTES];

    const uint8_t expected_round_keys[AES_128_NUM_KEY_BYTES * AES_128_NUM_ROUND_KEYS] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe,
        0xb6, 0x92, 0xcf, 0x0b, 0x64, 0x3d, 0xbd, 0xf1, 0xbe, 0x9b, 0xc5, 0x00, 0x68, 0x30, 0xb3, 0xfe,
        0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf, 0x6c, 0x59, 0x0c, 0xbf, 0x04, 0x69, 0xbf, 0x41,
        0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03, 0xf9, 0x6c, 0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd,
        0x3c, 0xaa, 0xa3, 0xe8, 0xa9, 0x9f, 0x9d, 0xeb, 0x50, 0xf3, 0xaf, 0x57, 0xad, 0xf6, 0x22, 0xaa,
        0x5e, 0x39, 0x0f, 0x7d, 0xf7, 0xa6, 0x92, 0x96, 0xa7, 0x55, 0x3d, 0xc1, 0x0a, 0xa3, 0x1f, 0x6b,
        0x14, 0xf9, 0x70, 0x1a, 0xe3, 0x5f, 0xe2, 0x8c, 0x44, 0x0a, 0xdf, 0x4d, 0x4e, 0xa9, 0xc0, 0x26,
        0x47, 0x43, 0x87, 0x35, 0xa4, 0x1c, 0x65, 0xb9, 0xe0, 0x16, 0xba, 0xf4, 0xae, 0xbf, 0x7a, 0xd2,
        0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85, 0x57, 0x68, 0x10, 0x93, 0xed, 0x9c, 0xbe, 0x2c, 0x97, 0x4e,
        0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17, 0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5
    };

    for (size_t i = 0; i < AES_128_NUM_ROUND_KEYS; ++i) {
        const uint8_t* start_expected_round_key = expected_round_keys + i * AES_128_NUM_KEY_BYTES;
        storeu(round_key, ctx.encryption_keys[i]);
        ASSERT_TRUE(utils::assert_equal(start_expected_round_key, round_key, AES_128_NUM_KEY_BYTES));
    }
}

// ---------------------------------------------------------

TEST(AES, test_encrypt_full) {
    const aes128_key_t key = { 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const aes_state_t plaintext = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const aes_state_t expected_ciphertext = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };
    run_encryption_test(key, plaintext, expected_ciphertext);
}

// ---------------------------------------------------------

TEST(AES, test_decrypt_full) {
    const aes128_key_t key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const aes_state_t ciphertext = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };
    const aes_state_t expected_plaintext = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    run_decryption_test(key, ciphertext, expected_plaintext);
}

// ---------------------------------------------------------

TEST(AES, test_encrypt_i_rounds) {
    const aes128_key_t key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const aes_state_t plaintext = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const aes_state_t expected_states[] = {
        { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
        { 0x89, 0xd8, 0x10, 0xe8, 0x85, 0x5a, 0xce, 0x68, 0x2d, 0x18, 0x43, 0xd8, 0xcb, 0x12, 0x8f, 0xe4 },
        { 0x49, 0x15, 0x59, 0x8f, 0x55, 0xe5, 0xd7, 0xa0, 0xda, 0xca, 0x94, 0xfa, 0x1f, 0x0a, 0x63, 0xf7 },
        { 0xfa, 0x63, 0x6a, 0x28, 0x25, 0xb3, 0x39, 0xc9, 0x40, 0x66, 0x8a, 0x31, 0x57, 0x24, 0x4d, 0x17 },
        { 0x24, 0x72, 0x40, 0x23, 0x69, 0x66, 0xb3, 0xfa, 0x6e, 0xd2, 0x75, 0x32, 0x88, 0x42, 0x5b, 0x6c },
        { 0xc8, 0x16, 0x77, 0xbc, 0x9b, 0x7a, 0xc9, 0x3b, 0x25, 0x02, 0x79, 0x92, 0xb0, 0x26, 0x19, 0x96 },
        { 0xc6, 0x2f, 0xe1, 0x09, 0xf7, 0x5e, 0xed, 0xc3, 0xcc, 0x79, 0x39, 0x5d, 0x84, 0xf9, 0xcf, 0x5d },
        { 0xd1, 0x87, 0x6c, 0x0f, 0x79, 0xc4, 0x30, 0x0a, 0xb4, 0x55, 0x94, 0xad, 0xd6, 0x6f, 0xf4, 0x1f },
        { 0xfd, 0xe3, 0xba, 0xd2, 0x05, 0xe5, 0xd0, 0xd7, 0x35, 0x47, 0x96, 0x4e, 0xf1, 0xfe, 0x37, 0xf1 },
        { 0xbd, 0x6e, 0x7c, 0x3d, 0xf2, 0xb5, 0x77, 0x9e, 0x0b, 0x61, 0x21, 0x6e, 0x8b, 0x10, 0xb6, 0x89 },
        { 0xd9, 0x61, 0xa1, 0x8c, 0xa9, 0x2d, 0xd9, 0x78, 0xfb, 0x98, 0x7b, 0x3a, 0xe7, 0xa8, 0xd9, 0xcd }
    };

    aes128_ctx_t ctx;
    aes128_key_setup(&ctx, key);
    
    for (size_t num_rounds = 0; num_rounds <= AES_128_NUM_ROUNDS; ++num_rounds) {
        aes_state_t ciphertext;
        aes128_encrypt_rounds_always_mc(
            &ctx, plaintext, ciphertext, num_rounds
        );
        ASSERT_TRUE(
            assert_equal(
                expected_states[num_rounds],
                ciphertext,
                (size_t)AES_NUM_STATE_BYTES
            )
        );
    }
}

// ---------------------------------------------------------

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// ---------------------------------------------------------
