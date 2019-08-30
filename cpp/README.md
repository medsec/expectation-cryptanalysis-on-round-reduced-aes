
# Extended Truncated-differential Cryptanalysis on Round-reduced AES and Small-AES

This repository contains the experiments for expectation cryptanalysis on round-reduced AES and its small-scale version [CMR05].

## Contents
The directory contains several C++ implementations. Some represent distinguishers, others are functional tests to verify our implementations.

### Distinguishers

- `tests/test_five_round_distinguisher_small.cc`
  The five-round expectation distinguisher on Small-AES that starts from $\delta$-sets of $2^8$ values of a single byte and counts the number of pairs that collide in at least one inverse diagonal after almost five rounds (the final MixColumns operation is neglected).
  
- `tests/test_five_round_non_delta_set_test.cc`
  Tests a randomness assumption as preparation step of the six-round expectation distinguisher on Small-AES. Given a structure of $2^{16} - \binom{2^4}{2}$ texts that iterate over all values of a column, tests all pairs that are active in more than one byte at the beginning and counts the number of pairs that collide in at least one inverse diagonal after almost five rounds (the final MixColumns operation is neglected).
   
- `tests/test_five_round_single_byte_distinguisher.cc`
  A test of a five-round distinguisher for the AES that tries to count the number of collisions in a single byte after five rounds. This produced no senseful result.

- `tests/test_five_round_single_byte_distinguisher_small.cc`
  A test of a five-round distinguisher for the Small-AES that tries to count the number of collisions in a single byte after five rounds. In experiments, it produced a multiple-of-4 property, which did not occur for the real AES, as illustrated in the test `test_five_round_single_byte_distinguisher`.

- `tests/test_four_round_distinguisher_small.cc`
  The four-round expectation distinguisher on Small-AES.

- `tests/test_four_round_id_distinguisher.cc`
  The four-round impossible-differential distinguisher on Small-AES.

- `tests/test_six_round_distinguisher_prp.cc`
  The (six-round-AES) expectation distinguisher with full Speck-64-96 for verification of the PRP behavior to find differences with `test_six_round_distinguisher_small`. Given a structure of $2^{16}$ texts that iterate over all values of a diagonal, counts the number of pairs that collide in at least one column.
   
- `tests/test_six_round_distinguisher_small.cc`
  The six-round expectation distinguisher on Small-AES. Given a structure of $2^{16}$ texts that iterate over all values of a diagonal, counts the number of pairs that collide in at least one column after almost five rounds (the final MixColumns and ShiftRows operations are neglected. Therefore, the program compares columns and not anti-diagonals).
    
- `tests/test_six_round_key_recovery_small.cc`
  The six-round expectation key-recovery attack on Small-AES. Extends `test_five_round_distinguisher_small` by a key-recovery phase. Given a structure of $2^{16}$ texts that iterate over all values of a diagonal, counts the number of pairs that collide in at least one inverse diagonal after almost five rounds (the final MixColumns operation is neglected). Outputs the $16$-bit keys in descending order of their counters.

### Usage
The distinguishers  provide a command-line interface for parameters, usually, the number of tested keys, number of plaintext sets per key. In some cases, a parameter also distinguishes whether the investigated cipher or a pseudo-random permutation shall be used.
Note the small argument parser shows only the long-string names for the options. Usually, you can also write single-character arguments `k` for the number of keys, `s` for the number of sets (attention: sometimes, their number is asked as the power of two, so that $4$ means $2^4 = 16$), and `r`, where `r 1` means use the pseudo-random primitive, and `r 0` means to use the non-random (real) primitive. 
For example, the following call runs the expectation distinguisher with $2^4$ keys on $100$ random keys each with the pseudo-random primitive:

    $ bin/test_four_round_distinguisher_small -k 100 -s 4 -r 1
    #Keys                100
    #Sets/Key (log)        4
    #Uses PRP              1
    Keys:    1 Collisions      131 Average 131.0000
    Keys:    2 Collisions      116 Average 123.5000
    Keys:    3 Collisions      120 Average 122.3333
    ...

### Functional Tests
The functional test verify the implementation of the used primitives---here AES-128, Small-AES, and Speck-64---as well as utilities that serve useful in our distinguishers:

- `tests/test_aes128.cc`
- `tests/test_small_aes.cc`
- `tests/test_speck64.cc`
- `tests/test_utils.cc`
- `tests/test_hash_table_generator.cc`

Our implementations of the AES and Small-AES employ AES-NI and AVX instruction sets for better performance. These processor features are usually supported if they are listed in

`cat /proc/cpuinfo | grep aes`

Replace `aes` by `avx` to see if AVX instructions are supported.

## Build

A `CMakeLists.txt` file is shipped that should allow you to build the tests above, if `CMake`, a C++ compiler, and `GTest` are installed.

In the root directory, type `cmake .` in a commandline/shell to build a make file. Thereupon, you can build the individual targets with `make <target>` where `<target>` is e.g., `test_five_round_distinguisher_small`, or build all by typing `make all`.

Executables will be placed in the directory `bin`.

## Dependencies

- `cmake` for building.
- `g++` or `clang++` as standard compiler. This can be customized in the `CMakeLists.txt` file.
- `gtest`: Google's unit test framework for the functional tests.
- `pthreads`: Needed by `gtest`.

### References

[CMR05] Carlos Cid, Sean Murphy, and Matthew J. B. Robshaw. Small Scale Variants of the AES. In Henri Gilbert and Helena Handschuh, editors, FSE, volume 3557 of Lecture Notes in Computer Science, pages 145–162. Springer, 2005.
