#!/bin/bash

PROGRAM=bin/test_six_round_distinguisher_small
OUT_DIR=results

# KEY=2121ce5b7037e676
KEY=65d98f7963409f20

for i in {0..8}
do
    FROM=$(( i * 3145728 + 10485760 ))
    TO=$(( (i + 1) * 3145728 + 10485760 ))
    nohup ${PROGRAM} -k 1 -s ${TO} -i ${FROM} -j ${KEY} > ${OUT_DIR}/aes_6_${KEY}_${FROM}_${TO}.txt &
done
