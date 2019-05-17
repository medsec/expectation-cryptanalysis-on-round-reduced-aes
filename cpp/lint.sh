#!/bin/bash
LINT_OUT_DIR=bin/linter
LINT_OUT_REPORT=linter_report.txt
LINTER=cpplint

mkdir -p ${LINT_OUT_DIR}
CC_FILES=$(find . -name '*.cc' -or -name '*.h')
echo $CC_FILES
${LINTER} --counting=detailed --output=vs7 --recursive --quiet --extensions=cpp,h,cc,mm,m --counting=detailed . &> ${LINT_OUT_DIR}/${LINT_OUT_REPORT}
