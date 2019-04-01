#!/usr/bin/make
# Intended for non-cmake-based build processes

CC=gcc
CXX=clang++
CXX_FLAGS=-W -Wall -Wextra -pedantic -fPIC -std=c++11 -mavx -maes -march=native -O3

TESTS_DIR=tests
SRC_DIR=src
INCLUDE_DIR=include
BIN_DIR=bin

.PHONY: clean all test_six_round_distinguisher_small test_six_round_key_recovery_small

all: test_six_round_distinguisher_small

$(SRC_DIR)/ciphers/%.o: $(SRC_DIR)/ciphers/%.cc
	$(CXX) -c $(CXX_FLAGS) -I$(INCLUDE_DIR) -I$(SRC_DIR) $< -o $@

$(SRC_DIR)/utils/%.o: $(SRC_DIR)/utils/%.cc
	$(CXX) -c $(CXX_FLAGS) -I$(INCLUDE_DIR) -I$(SRC_DIR) $< -o $@

test_six_round_key_recovery_small: $(SRC_DIR)/ciphers/small_aes.o $(SRC_DIR)/utils/utils.o $(SRC_DIR)/utils/hash_table_generator.o $(SRC_DIR)/utils/product.o
	$(CXX) $(CXX_FLAGS) $(TESTS_DIR)/$@.cc -I$(INCLUDE_DIR) -I$(SRC_DIR) $(SRC_DIR)/ciphers/small_aes.o $(SRC_DIR)/utils/utils.o $(SRC_DIR)/utils/hash_table_generator.o $(SRC_DIR)/utils/product.o -o $(BIN_DIR)/$@

test_six_round_distinguisher_small: $(SRC_DIR)/ciphers/small_aes.o $(SRC_DIR)/utils/utils.o
	$(CXX) $(CXX_FLAGS) $(TESTS_DIR)/$@.cc -I$(INCLUDE_DIR) -I$(SRC_DIR) $(SRC_DIR)/ciphers/small_aes.o $(SRC_DIR)/utils/utils.o -o $(BIN_DIR)/$@
