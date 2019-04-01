/**
 * __author__ = anonymized
 * __date__   = 2018-03-31
 * __copyright__ = CC0
 */

#include <gtest/gtest.h>
#include <stdint.h>


#include "ciphers/small_aes.h"
#include "utils/hash_table_generator.h"
#include "utils/utils.h"


using namespace ciphers;
using namespace utils;

// ---------------------------------------------------------

TEST(HashTableGenerator, create_extended_ddt) {
    std::vector<std::vector<IntegerList> > extended_ddt;
    HashTableGenerator generator;

    generator.compute_extended_ddt(extended_ddt, SMALL_AES_INVERSE_SBOX_ARRAY, 16);
    ExtendedDDT expected_ddt = {
        {
            { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf },
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
        },
        {
            {},
            { 0x4, 0x5 },
            { 0xc, 0xd },
            { 0x0, 0x1 },
            {},
            {},
            { 0x6, 0x7, 0xa, 0xb },
            { 0x8, 0x9 },
            { 0x2, 0x3 },
            {},
            {},
            {},
            {},
            {},
            {},
            { 0xe, 0xf }
        }
    };

    for (size_t delta_x = 0; delta_x < expected_ddt.size(); ++delta_x) {
        const IntegerMatrix& values_delta_x = expected_ddt[delta_x];

        for (size_t delta_y = 0; delta_y < values_delta_x.size(); ++delta_y) {
            const IntegerList &values_delta_xy = values_delta_x[delta_y];

            ASSERT_EQ(
                values_delta_xy.size(),
                extended_ddt[delta_x][delta_y].size()
            );

            for (size_t i = 0; i < values_delta_xy.size(); ++i) {
                ASSERT_EQ(
                    expected_ddt[delta_x][delta_y][i],
                    extended_ddt[delta_x][delta_y][i]
                );
            }
        }
    }
}

// ---------------------------------------------------------

static void test_hash_table(const size_t tested_delta_ins[],
                            const std::vector<IntegerMatrix>& expected_transitions,
                            const std::vector<IntegerMatrix>& hash_table) {

    for (size_t i = 0; i < expected_transitions.size(); ++i) {
        const size_t tested_delta_in = tested_delta_ins[i];
        const IntegerMatrix& actual_transitions = hash_table[tested_delta_in];

        for (size_t j = 0; j < expected_transitions[i].size(); ++j) {
            for (size_t k = 0; k < expected_transitions[i][j].size(); ++k) {
                ASSERT_EQ(expected_transitions[i][j][k], actual_transitions[j][k]);
            }
        }
    }
}

// ---------------------------------------------------------

TEST(HashTableGenerator, create_hash_table_0) {
    ExtendedDDT extended_ddt;
    HashTableGenerator generator;

    generator.compute_extended_ddt(extended_ddt, SMALL_AES_INVERSE_SBOX_ARRAY, 16);
    std::vector<IntegerMatrix> hash_table;
    generator.create_hash_table(hash_table, 0, extended_ddt);

    const size_t tested_delta_ins[] = {
        0x0000, 0x0001, 0x0010, 0x0100, 0x1010, 0x1111, 0x2222, 0x3ee7,
        0x50ef, 0xfefe
    };
    const std::vector<IntegerMatrix> expected_transitions = {
        {},
        {},
        {},
        {},
        {},
        {
            {12, 0, 2, 14}, {12, 0, 2, 15}, {12, 0, 3, 14}, {12, 0, 3, 15},
            {12, 1, 2, 14}, {12, 1, 2, 15}, {12, 1, 3, 14}, {12, 1, 3, 15},
            {13, 0, 2, 14}, {13, 0, 2, 15}, {13, 0, 3, 14}, {13, 0, 3, 15},
            {13, 1, 2, 14}, {13, 1, 2, 15}, {13, 1, 3, 14}, {13, 1, 3, 15}
        },
        {
            {1, 8, 5, 12}, {1, 8, 5, 14}, {1, 8, 7, 12}, {1, 8, 7, 14},
            {1, 10, 5, 12}, {1, 10, 5, 14}, {1, 10, 7, 12}, {1, 10, 7, 14},
            {3, 8, 5, 12}, {3, 8, 5, 14}, {3, 8, 7, 12}, {3, 8, 7, 14},
            {3, 10, 5, 12}, {3, 10, 5, 14}, {3, 10, 7, 12}, {3, 10, 7, 14}
        },
        {},
        {},
        {
            {4, 5, 1, 2}, {4, 5, 1, 6}, {4, 5, 1, 8}, {4, 5, 1, 12},
            {4, 5, 6, 2}, {4, 5, 6, 6}, {4, 5, 6, 8}, {4, 5, 6, 12},
            {4, 5, 9, 2}, {4, 5, 9, 6}, {4, 5, 9, 8}, {4, 5, 9, 12},
            {4, 5, 14, 2}, {4, 5, 14, 6}, {4, 5, 14, 8}, {4, 5, 14, 12},
            {4, 11, 1, 2}, {4, 11, 1, 6}, {4, 11, 1, 8}, {4, 11, 1, 12},
            {4, 11, 6, 2}, {4, 11, 6, 6}, {4, 11, 6, 8}, {4, 11, 6, 12},
            {4, 11, 9, 2}, {4, 11, 9, 6}, {4, 11, 9, 8}, {4, 11, 9, 12},
            {4, 11, 14, 2}, {4, 11, 14, 6}, {4, 11, 14, 8}, {4, 11, 14, 12},
            {11, 5, 1, 2}, {11, 5, 1, 6}, {11, 5, 1, 8}, {11, 5, 1, 12},
            {11, 5, 6, 2}, {11, 5, 6, 6}, {11, 5, 6, 8}, {11, 5, 6, 12},
            {11, 5, 9, 2}, {11, 5, 9, 6}, {11, 5, 9, 8}, {11, 5, 9, 12},
            {11, 5, 14, 2}, {11, 5, 14, 6}, {11, 5, 14, 8}, {11, 5, 14, 12},
            {11, 11, 1, 2}, {11, 11, 1, 6}, {11, 11, 1, 8}, {11, 11, 1, 12},
            {11, 11, 6, 2}, {11, 11, 6, 6}, {11, 11, 6, 8}, {11, 11, 6, 12},
            {11, 11, 9, 2}, {11, 11, 9, 6}, {11, 11, 9, 8}, {11, 11, 9, 12},
            {11, 11, 14, 2}, {11, 11, 14, 6}, {11, 11, 14, 8}, {11, 11, 14, 12},
            {7, 4, 4, 1}, {7, 4, 4, 15}, {7, 4, 11, 1}, {7, 4, 11, 15},
            {7, 10, 4, 1}, {7, 10, 4, 15}, {7, 10, 11, 1}, {7, 10, 11, 15},
            {8, 4, 4, 1}, {8, 4, 4, 15}, {8, 4, 11, 1}, {8, 4, 11, 15},
            {8, 10, 4, 1}, {8, 10, 4, 15}, {8, 10, 11, 1}, {8, 10, 11, 15},
            {5, 7, 3, 5}, {5, 7, 3, 11}, {5, 7, 12, 5}, {5, 7, 12, 11},
            {5, 9, 3, 5}, {5, 9, 3, 11}, {5, 9, 12, 5}, {5, 9, 12, 11},
            {10, 7, 3, 5}, {10, 7, 3, 11}, {10, 7, 12, 5}, {10, 7, 12, 11},
            {10, 9, 3, 5}, {10, 9, 3, 11}, {10, 9, 12, 5}, {10, 9, 12, 11}
        }
    };

    test_hash_table(tested_delta_ins, expected_transitions, hash_table);
}

// ---------------------------------------------------------

TEST(HashTableGenerator, create_hash_table_1) {
    ExtendedDDT extended_ddt;
    HashTableGenerator generator;

    generator.compute_extended_ddt(extended_ddt, SMALL_AES_INVERSE_SBOX_ARRAY, 16);
    std::vector<IntegerMatrix> hash_table;
    generator.create_hash_table(hash_table, 1, extended_ddt);

    const size_t tested_delta_ins[] = {
        0x0000, 0x0001, 0x0010, 0x0100, 0x1010, 0x1111, 0x2222, 0x3ee7,
        0x50ef, 0xfefe
    };
    const std::vector<IntegerMatrix> expected_transitions = {
        {},
        {},
        {},
        {},
        {},
        {
            {14, 12, 0, 2}, {14, 12, 0, 3}, {14, 12, 1, 2}, {14, 12, 1, 3},
            {14, 13, 0, 2}, {14, 13, 0, 3}, {14, 13, 1, 2}, {14, 13, 1, 3},
            {15, 12, 0, 2}, {15, 12, 0, 3}, {15, 12, 1, 2}, {15, 12, 1, 3},
            {15, 13, 0, 2}, {15, 13, 0, 3}, {15, 13, 1, 2}, {15, 13, 1, 3}
        },
        {
            {12, 1, 8, 5}, {12, 1, 8, 7}, {12, 1, 10, 5}, {12, 1, 10, 7},
            {12, 3, 8, 5}, {12, 3, 8, 7}, {12, 3, 10, 5}, {12, 3, 10, 7},
            {14, 1, 8, 5}, {14, 1, 8, 7}, {14, 1, 10, 5}, {14, 1, 10, 7},
            {14, 3, 8, 5}, {14, 3, 8, 7}, {14, 3, 10, 5}, {14, 3, 10, 7}
        },
        {},
        {},
        {}
    };

    test_hash_table(tested_delta_ins, expected_transitions, hash_table);
}

// ---------------------------------------------------------

TEST(HashTableGenerator, create_hash_table_2) {
    ExtendedDDT extended_ddt;
    HashTableGenerator generator;

    generator.compute_extended_ddt(extended_ddt, SMALL_AES_INVERSE_SBOX_ARRAY, 16);
    std::vector<IntegerMatrix> hash_table;
    generator.create_hash_table(hash_table, 2, extended_ddt);

    const size_t tested_delta_ins[] = {
        0x0000, 0x0001, 0x0010, 0x0100, 0x1010, 0x1111, 0x2222, 0x3ee7,
        0x50ef, 0xfefe
    };
    const std::vector<IntegerMatrix> expected_transitions = {
        {},
        {},
        {},
        {},
        {},
        {
             {2, 14, 12, 0}, {2, 14, 12, 1}, {2, 14, 13, 0}, {2, 14, 13, 1},
             {2, 15, 12, 0}, {2, 15, 12, 1}, {2, 15, 13, 0}, {2, 15, 13, 1},
             {3, 14, 12, 0}, {3, 14, 12, 1}, {3, 14, 13, 0}, {3, 14, 13, 1},
             {3, 15, 12, 0}, {3, 15, 12, 1}, {3, 15, 13, 0}, {3, 15, 13, 1}
        },
        {
            {5, 12, 1, 8}, {5, 12, 1, 10}, {5, 12, 3, 8}, {5, 12, 3, 10},
            {5, 14, 1, 8}, {5, 14, 1, 10}, {5, 14, 3, 8}, {5, 14, 3, 10},
            {7, 12, 1, 8}, {7, 12, 1, 10}, {7, 12, 3, 8}, {7, 12, 3, 10},
            {7, 14, 1, 8}, {7, 14, 1, 10}, {7, 14, 3, 8}, {7, 14, 3, 10}
        },
        {},
        {},
        {
            {1, 2, 4, 5}, {1, 2, 4, 11}, {1, 2, 11, 5}, {1, 2, 11, 11},
            {1, 6, 4, 5}, {1, 6, 4, 11}, {1, 6, 11, 5}, {1, 6, 11, 11},
            {1, 8, 4, 5}, {1, 8, 4, 11}, {1, 8, 11, 5}, {1, 8, 11, 11},
            {1, 12, 4, 5}, {1, 12, 4, 11}, {1, 12, 11, 5}, {1, 12, 11, 11},
            {6, 2, 4, 5}, {6, 2, 4, 11}, {6, 2, 11, 5}, {6, 2, 11, 11},
            {6, 6, 4, 5}, {6, 6, 4, 11}, {6, 6, 11, 5}, {6, 6, 11, 11},
            {6, 8, 4, 5}, {6, 8, 4, 11}, {6, 8, 11, 5}, {6, 8, 11, 11},
            {6, 12, 4, 5}, {6, 12, 4, 11}, {6, 12, 11, 5}, {6, 12, 11, 11},
            {9, 2, 4, 5}, {9, 2, 4, 11}, {9, 2, 11, 5}, {9, 2, 11, 11},
            {9, 6, 4, 5}, {9, 6, 4, 11}, {9, 6, 11, 5}, {9, 6, 11, 11},
            {9, 8, 4, 5}, {9, 8, 4, 11}, {9, 8, 11, 5}, {9, 8, 11, 11},
            {9, 12, 4, 5}, {9, 12, 4, 11}, {9, 12, 11, 5}, {9, 12, 11, 11},
            {14, 2, 4, 5}, {14, 2, 4, 11}, {14, 2, 11, 5}, {14, 2, 11, 11},
            {14, 6, 4, 5}, {14, 6, 4, 11}, {14, 6, 11, 5}, {14, 6, 11, 11},
            {14, 8, 4, 5}, {14, 8, 4, 11}, {14, 8, 11, 5}, {14, 8, 11, 11},
            {14, 12, 4, 5}, {14, 12, 4, 11}, {14, 12, 11, 5}, {14, 12, 11, 11},
            {4, 1, 7, 4}, {4, 1, 7, 10}, {4, 1, 8, 4}, {4, 1, 8, 10},
            {4, 15, 7, 4}, {4, 15, 7, 10}, {4, 15, 8, 4}, {4, 15, 8, 10},
            {11, 1, 7, 4}, {11, 1, 7, 10}, {11, 1, 8, 4}, {11, 1, 8, 10},
            {11, 15, 7, 4}, {11, 15, 7, 10}, {11, 15, 8, 4}, {11, 15, 8, 10},
            {3, 5, 5, 7}, {3, 5, 5, 9}, {3, 5, 10, 7}, {3, 5, 10, 9},
            {3, 11, 5, 7}, {3, 11, 5, 9}, {3, 11, 10, 7}, {3, 11, 10, 9},
            {12, 5, 5, 7}, {12, 5, 5, 9}, {12, 5, 10, 7}, {12, 5, 10, 9},
            {12, 11, 5, 7}, {12, 11, 5, 9}, {12, 11, 10, 7}, {12, 11, 10, 9}
        }
    };

    test_hash_table(tested_delta_ins, expected_transitions, hash_table);
}

// ---------------------------------------------------------

TEST(HashTableGenerator, create_hash_table_3) {
    ExtendedDDT extended_ddt;
    HashTableGenerator generator;

    generator.compute_extended_ddt(extended_ddt, SMALL_AES_INVERSE_SBOX_ARRAY, 16);
    std::vector<IntegerMatrix> hash_table;
    generator.create_hash_table(hash_table, 3, extended_ddt);

    const size_t tested_delta_ins[] = {
        0x0000, 0x0001, 0x0010, 0x0100, 0x1010, 0x1111, 0x2222, 0x3ee7,
        0x50ef, 0xfefe
    };
    const std::vector<IntegerMatrix> expected_transitions = {
        {},
        {},
        {},
        {},
        {},
        {
            {0, 2, 14, 12}, {0, 2, 14, 13}, {0, 2, 15, 12}, {0, 2, 15, 13},
            {0, 3, 14, 12}, {0, 3, 14, 13}, {0, 3, 15, 12}, {0, 3, 15, 13},
            {1, 2, 14, 12}, {1, 2, 14, 13}, {1, 2, 15, 12}, {1, 2, 15, 13},
            {1, 3, 14, 12}, {1, 3, 14, 13}, {1, 3, 15, 12}, {1, 3, 15, 13}
        },
        {
            {8, 5, 12, 1}, {8, 5, 12, 3}, {8, 5, 14, 1}, {8, 5, 14, 3},
            {8, 7, 12, 1}, {8, 7, 12, 3}, {8, 7, 14, 1}, {8, 7, 14, 3},
            {10, 5, 12, 1}, {10, 5, 12, 3}, {10, 5, 14, 1}, {10, 5, 14, 3},
            {10, 7, 12, 1}, {10, 7, 12, 3}, {10, 7, 14, 1}, {10, 7, 14, 3}
        },
        {
            {8, 1, 5, 8}, {8, 1, 5, 15}, {8, 1, 11, 8}, {8, 1, 11, 15},
            {8, 15, 5, 8}, {8, 15, 5, 15}, {8, 15, 11, 8}, {8, 15, 11, 15},
            {11, 1, 5, 8}, {11, 1, 5, 15}, {11, 1, 11, 8}, {11, 1, 11, 15},
            {11, 15, 5, 8}, {11, 15, 5, 15}, {11, 15, 11, 8}, {11, 15, 11, 15}
        },
        {},
        {}
    };

    test_hash_table(tested_delta_ins, expected_transitions, hash_table);
}

// ---------------------------------------------------------

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
