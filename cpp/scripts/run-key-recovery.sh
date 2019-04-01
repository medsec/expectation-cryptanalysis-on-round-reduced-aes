#!/bin/bash

PROGRAM=bin/test_six_round_key_recovery_small
OUT_DIR=results
NUM_STRUCTURES=32768

for i in {1..10}
do
    nohup ${PROGRAM} -k 10 -s ${NUM_STRUCTURES} > ${OUT_DIR}/mean-6_aes-small_key-recovery_${NUM_STRUCTURES}_${i}.txt &
done
