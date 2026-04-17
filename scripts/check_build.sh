#!/bin/bash
if [ -f /work/llvm_build.log ]; then
    echo "=== LLVM 빌드 진행 상황 ==="
    echo "마지막 10줄:"
    tail -10 /work/llvm_build.log
    echo ""
    echo "진행률 검색:"
    grep -o '\[.*%\]' /work/llvm_build.log | tail -1
    echo ""
    echo "에러 확인:"
    grep -i "error:" /work/llvm_build.log | tail -3 || echo "(에러 없음)"
else
    echo "빌드 로그 없음"
fi
