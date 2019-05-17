/**
 * __author__ = anonymized
 * __date__   = 2019-05
 * __copyright__ = Creative Commons CC0
 */

#include <stdint.h>
#include <gtest/gtest.h>

#include "ciphers/small_aes.h"
#include "utils/utils.h"


using ciphers::small_aes_ctx_t;
using ciphers::small_aes_key_t;
using ciphers::small_aes_state_t;
using utils::assert_equal;

// ---------------------------------------------------------

static void run_encryption_test(const small_aes_key_t key,
                                const small_aes_state_t plaintext,
                                const small_aes_state_t expected_ciphertext) {
    small_aes_ctx_t ctx;
    small_aes_key_setup(&ctx, key);

    small_aes_state_t ciphertext;
    small_aes_encrypt(&ctx, plaintext, ciphertext);
    ASSERT_TRUE(assert_equal(expected_ciphertext, ciphertext,
                             (size_t) SMALL_AES_NUM_STATE_BYTES));
}

// ---------------------------------------------------------

static void run_decryption_test(const small_aes_key_t key,
                                const small_aes_state_t ciphertext,
                                const small_aes_state_t expected_plaintext) {
    small_aes_ctx_t ctx;
    small_aes_key_setup(&ctx, key);

    small_aes_state_t plaintext;
    small_aes_decrypt(&ctx, ciphertext, plaintext);
    ASSERT_TRUE(assert_equal(expected_plaintext, plaintext,
                             (size_t) SMALL_AES_NUM_STATE_BYTES));
}

// ---------------------------------------------------------

static void run_encryption_test_of_two(
    const small_aes_key_t key,
    const uint8_t plaintexts[2 * SMALL_AES_NUM_STATE_BYTES],
    const uint8_t expected_ciphertexts[2 * SMALL_AES_NUM_STATE_BYTES]) {
    small_aes_ctx_t ctx;
    small_aes_key_setup(&ctx, key);
    small_aes_key_setup_2(&ctx);

    uint8_t ciphertexts[2 * SMALL_AES_NUM_STATE_BYTES];
    small_aes_encrypt_2(&ctx, plaintexts, ciphertexts);
    ASSERT_TRUE(assert_equal(expected_ciphertexts, ciphertexts,
                             (size_t) (2 * SMALL_AES_NUM_STATE_BYTES)));
}

// ---------------------------------------------------------

static void run_encryption_test_of_four(
    const small_aes_key_t key,
    const uint8_t plaintexts[4 * SMALL_AES_NUM_STATE_BYTES],
    const uint8_t expected_ciphertexts[4 * SMALL_AES_NUM_STATE_BYTES]) {
    small_aes_ctx_t ctx;
    small_aes_key_setup(&ctx, key);
    small_aes_key_setup_4(&ctx);

    uint8_t ciphertexts[4 * SMALL_AES_NUM_STATE_BYTES];
    small_aes_encrypt_4(&ctx, plaintexts, ciphertexts);
    ASSERT_TRUE(assert_equal(expected_ciphertexts, ciphertexts,
                             (size_t) (4 * SMALL_AES_NUM_STATE_BYTES)));
}

// ---------------------------------------------------------

TEST(Small_AES, test_key_schedule) {
    const small_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    small_aes_ctx_t ctx;
    small_aes_key_setup(&ctx, key);

    uint8_t round_key[16];

    const uint8_t expected_round_keys[16 * SMALL_AES_NUM_ROUND_KEYS] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x00, 0x01, 0x0a, 0x00, 0x04, 0x04, 0x0c, 0x07,
        0x0c, 0x0d, 0x06, 0x0c, 0x00, 0x00, 0x08, 0x03,
        0x04, 0x08, 0x0e, 0x06, 0x00, 0x0c, 0x02, 0x01,
        0x0c, 0x01, 0x04, 0x0d, 0x0c, 0x01, 0x0c, 0x0e,
        0x0b, 0x0b, 0x0e, 0x05, 0x0b, 0x07, 0x0c, 0x04,
        0x07, 0x06, 0x08, 0x09, 0x0b, 0x07, 0x04, 0x07,
        0x09, 0x09, 0x04, 0x09, 0x02, 0x0e, 0x08, 0x0d,
        0x05, 0x08, 0x00, 0x04, 0x0e, 0x0f, 0x04, 0x03,
        0x02, 0x0b, 0x00, 0x09, 0x00, 0x05, 0x08, 0x04,
        0x05, 0x0d, 0x08, 0x00, 0x0b, 0x02, 0x0c, 0x03,
        0x01, 0x08, 0x04, 0x05, 0x01, 0x0d, 0x0c, 0x01,
        0x04, 0x00, 0x04, 0x01, 0x0f, 0x02, 0x08, 0x02,
        0x08, 0x01, 0x01, 0x0d, 0x09, 0x0c, 0x0d, 0x0c,
        0x0d, 0x0c, 0x09, 0x0d, 0x02, 0x0e, 0x01, 0x0f,
        0x03, 0x0a, 0x09, 0x08, 0x0a, 0x06, 0x04, 0x04,
        0x07, 0x0a, 0x0d, 0x09, 0x05, 0x04, 0x0c, 0x06,
        0x04, 0x09, 0x0e, 0x06, 0x0e, 0x0f, 0x0a, 0x02,
        0x09, 0x05, 0x07, 0x0b, 0x0c, 0x01, 0x0b, 0x0d,
        0x05, 0x05, 0x0f, 0x05, 0x0b, 0x0a, 0x05, 0x07,
        0x02, 0x0f, 0x02, 0x0c, 0x0e, 0x0e, 0x09, 0x01
    };

    for (size_t i = 0; i < SMALL_AES_NUM_ROUND_KEYS; ++i) {
        const uint8_t *start_expected_round_key = expected_round_keys + i * 16;
        storeu(round_key, ctx.key[i]);
        ASSERT_TRUE(assert_equal(start_expected_round_key, round_key, 16));
    }
}

// ---------------------------------------------------------

TEST(Small_AES, test_encrypt_full) {
    const small_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const small_aes_state_t plaintext = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const small_aes_state_t expected_ciphertext = {
        0x44, 0xfd, 0x3f, 0x91, 0x2a, 0x26, 0x84, 0xbc
    };
    run_encryption_test(key, plaintext, expected_ciphertext);
}

// ---------------------------------------------------------

TEST(Small_AES, test_encrypt_full_second) {
    const small_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const small_aes_state_t plaintext = {
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const small_aes_state_t expected_ciphertext = {
        0x0c, 0x6e, 0xbf, 0x41, 0x20, 0x58, 0x9a, 0x74
    };
    run_encryption_test(key, plaintext, expected_ciphertext);
}

// ---------------------------------------------------------

TEST(Small_AES, test_encrypt_full_third) {
    const small_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const small_aes_state_t plaintext = {
        0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98
    };
    const small_aes_state_t expected_ciphertext = {
        0x19, 0xaa, 0x15, 0x27, 0xa8, 0x0f, 0xf6, 0x5b
    };
    run_encryption_test(key, plaintext, expected_ciphertext);
}

// ---------------------------------------------------------

TEST(Small_AES, test_encrypt_full_fourth) {
    const small_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const small_aes_state_t plaintext = {
        0x76, 0x54, 0xfe, 0xdc, 0x32, 0x10, 0xba, 0x98
    };
    const small_aes_state_t expected_ciphertext = {
        0x11, 0x91, 0xfb, 0xad, 0x8a, 0x33, 0x84, 0x6a
    };
    run_encryption_test(key, plaintext, expected_ciphertext);
}

// ---------------------------------------------------------

TEST(Small_AES, test_encrypt_i_rounds) {
    const small_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const small_aes_state_t plaintext = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const size_t num_bytes =
        (SMALL_AES_NUM_ROUNDS + 1) * SMALL_AES_NUM_STATE_BYTES;
    const uint8_t expected_states[num_bytes] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x67, 0xc6, 0x22, 0xa1, 0xab, 0x0a, 0x66, 0xe5,
        0xd1, 0x13, 0xa5, 0x2c, 0x0e, 0x4e, 0xfc, 0xef,
        0x2b, 0xe9, 0x2c, 0xfe, 0x6b, 0xdd, 0x35, 0xd2,
        0x2c, 0xfe, 0x3e, 0x76, 0xa0, 0x93, 0x8a, 0xc9,
        0x87, 0x82, 0x18, 0xcd, 0x53, 0x2b, 0x14, 0xda,
        0x20, 0xcc, 0xc8, 0xe0, 0x53, 0xa9, 0x87, 0x8e,
        0x57, 0x04, 0x9c, 0xe2, 0xa6, 0x19, 0x46, 0xa8,
        0xb5, 0x90, 0x75, 0x5c, 0x04, 0x60, 0x1c, 0x03,
        0xd7, 0xe0, 0xfd, 0x47, 0xe2, 0xe9, 0x02, 0xbf,
        0xce, 0x44, 0xd9, 0x99, 0x7f, 0xae, 0x04, 0x5a
    };

    small_aes_ctx_t ctx;
    small_aes_key_setup(&ctx, key);

    for (size_t num_rounds = 0;
         num_rounds <= SMALL_AES_NUM_ROUNDS; ++num_rounds) {
        small_aes_state_t ciphertext;
        small_aes_encrypt_rounds_always_mc(
            &ctx, plaintext, ciphertext, num_rounds
        );
        ASSERT_TRUE(
            assert_equal(
                &(expected_states[num_rounds * SMALL_AES_NUM_STATE_BYTES]),
                ciphertext,
                (size_t) SMALL_AES_NUM_STATE_BYTES
            )
        );
    }
}

// ---------------------------------------------------------

TEST(Small_AES, test_decrypt_full) {
    const small_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const small_aes_state_t ciphertext = {
        0x44, 0xfd, 0x3f, 0x91, 0x2a, 0x26, 0x84, 0xbc
    };
    const small_aes_state_t expected_plaintext = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    run_decryption_test(key, ciphertext, expected_plaintext);
}

// ---------------------------------------------------------

TEST(Small_AES, test_encrypt_full_2_blocks) {
    const small_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const uint8_t plaintexts[2 * SMALL_AES_NUM_STATE_BYTES] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const uint8_t expected_ciphertexts[2 * SMALL_AES_NUM_STATE_BYTES] = {
        0x44, 0xfd, 0x3f, 0x91, 0x2a, 0x26, 0x84, 0xbc,
        0x0c, 0x6e, 0xbf, 0x41, 0x20, 0x58, 0x9a, 0x74
    };
    run_encryption_test_of_two(key, plaintexts, expected_ciphertexts);
}

// ---------------------------------------------------------

TEST(Small_AES, test_encrypt_full_4_blocks) {
    const small_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const uint8_t plaintexts[4 * SMALL_AES_NUM_STATE_BYTES] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0xfe, 0xdc, 0x32, 0x10, 0xba, 0x98
    };
    const uint8_t expected_ciphertexts[4 * SMALL_AES_NUM_STATE_BYTES] = {
        0x44, 0xfd, 0x3f, 0x91, 0x2a, 0x26, 0x84, 0xbc,
        0x0c, 0x6e, 0xbf, 0x41, 0x20, 0x58, 0x9a, 0x74,
        0x19, 0xaa, 0x15, 0x27, 0xa8, 0x0f, 0xf6, 0x5b,
        0x11, 0x91, 0xfb, 0xad, 0x8a, 0x33, 0x84, 0x6a
    };
    run_encryption_test_of_four(key, plaintexts, expected_ciphertexts);
}

// ---------------------------------------------------------

TEST(Small_AES, test_encrypt_4_blocks_only_sbox_in_final) {
    const small_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const uint8_t plaintexts[4 * SMALL_AES_NUM_STATE_BYTES] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0xfe, 0xdc, 0x32, 0x10, 0xba, 0x98
    };
    const uint8_t expected_ciphertexts[4 * SMALL_AES_NUM_STATE_BYTES] = {
        0x82, 0xd0, 0xa4, 0xf0, 0xa4, 0x1d, 0x40, 0x9d,
        0xfe, 0x1d, 0xb1, 0x4c, 0xb4, 0x0b, 0xde, 0x00,
        0xde, 0x31, 0x90, 0x34, 0xcb, 0xfa, 0xfe, 0xf3,
        0x73, 0xba, 0x16, 0x67, 0x24, 0xdf, 0x09, 0x3b
    };
    const size_t num_rounds = 6;

    small_aes_ctx_t ctx;
    small_aes_key_setup(&ctx, key);
    small_aes_key_setup_4(&ctx);

    uint8_t ciphertexts[4 * SMALL_AES_NUM_STATE_BYTES];
    small_aes_encrypt_rounds_4_only_sbox_in_final(&ctx, plaintexts, ciphertexts,
                                                  num_rounds);
    ASSERT_TRUE(assert_equal(expected_ciphertexts,
                             ciphertexts,
                             (size_t) (4 * SMALL_AES_NUM_STATE_BYTES)));
}

// ---------------------------------------------------------

TEST(Small_AES, test_encrypt_6_rounds_only_sbox_in_final) {
    const small_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const small_aes_state_t plaintext = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const small_aes_state_t expected_ciphertext = {
        0x82, 0xd0, 0xa4, 0xf0, 0xa4, 0x1d, 0x40, 0x9d
    };
    const size_t num_rounds = 6;

    small_aes_ctx_t ctx;
    small_aes_key_setup(&ctx, key);

    small_aes_state_t ciphertext;
    small_aes_encrypt_rounds_only_sbox_in_final(&ctx, plaintext, ciphertext,
                                                num_rounds);
    ASSERT_TRUE(assert_equal(expected_ciphertext,
                             ciphertext,
                             (size_t) (SMALL_AES_NUM_STATE_BYTES)));
}

// ---------------------------------------------------------

TEST(Small_AES, test_encrypt_6_rounds_only_sbox_in_final_with_aes_ni) {
    const small_aes_key_t key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const __m128i plaintext = vsetr8(
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    );
    const __m128i expected_ciphertext = vsetr8(
        0x08, 0x02, 0x0d, 0x00, 0x0a, 0x04, 0x0f, 0x00,
        0x0a, 0x04, 0x01, 0x0d, 0x04, 0x00, 0x09, 0x0d
    );
    const size_t num_rounds = 6;

    small_aes_ctx_t ctx;
    small_aes_key_setup(&ctx, key);

    __m128i ciphertext =
        small_aes_encrypt_rounds_only_sbox_in_final_with_aes_ni(&ctx,
            plaintext,
            num_rounds
        );
    ASSERT_TRUE(vare_equal(expected_ciphertext, ciphertext));
}

// ---------------------------------------------------------

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// ---------------------------------------------------------
