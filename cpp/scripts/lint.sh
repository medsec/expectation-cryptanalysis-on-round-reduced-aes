#!/bin/bash
LINT_OUT_DIR=bin/linter
LINT_OUT_REPORT=linter_report.txt
LINTER=cpplint

mkdir -p ${LINT_OUT_DIR}
${LINTER} --counting=detailed --output=vs7 ./**/*.cc &> ${LINT_OUT_DIR}/${LINT_OUT_REPORT}
${LINTER} --counting=detailed --output=vs7 ./**/*.h &>> ${LINT_OUT_DIR}/${LINT_OUT_REPORT}
