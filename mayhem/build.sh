#!/usr/bin/env bash
#
# mayhem/build.sh — build the usrsctp fuzz harnesses (sanitized, libFuzzer + standalone) and the
# functional self-test (normal flags). Runs in /mayhem as `mayhem`; re-runnable and offline.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# 1) The library, sanitized + DWARF<=3, with sancov instrumentation (-fsanitize=fuzzer-no-link is added
#    by upstream's sctp_build_fuzzer option). Same configuration OSS-Fuzz uses (invariants on, debug off).
#    The build dirs live under build/, which upstream's .gitignore covers.
rm -rf build/fuzz
cmake -S . -B build/fuzz -DCMAKE_C_COMPILER="$CC" \
      -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
      -Dsctp_build_programs=0 -Dsctp_build_fuzzer=1 -Dsctp_debug=0 -Dsctp_invariants=1 -Dsctp_werror=0
cmake --build build/fuzz -j"$MAYHEM_JOBS" --target usrsctp

# 2) The three upstream harnesses, each linked twice: libFuzzer and standalone reproducer.
#    LeakSanitizer is turned off at build time by linking lsan_off.o.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o build/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/standalone_main.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/programs/programs_helper.c" -I"$SRC/usrsctplib" -o build/programs_helper.o

for t in fuzzer_connect fuzzer_fragment fuzzer_listen; do
    stage=
    [ "$t" != fuzzer_connect ] || stage=-DFUZZING_STAGE=0
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $stage -D_GNU_SOURCE -I"$SRC/fuzzer" -I"$SRC/usrsctplib" \
        -c "$SRC/fuzzer/$t.c" -o "build/$t.o"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "build/$t.o" build/programs_helper.o \
        build/lsan_off.o build/fuzz/usrsctplib/libusrsctp.a -lpthread -o "/mayhem/$t"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "build/$t.o" build/programs_helper.o build/standalone_main.o \
        build/lsan_off.o build/fuzz/usrsctplib/libusrsctp.a -lpthread -o "/mayhem/$t-standalone"
done

# 3) The functional self-test, with the project's NORMAL flags (no sanitizers, no fuzzer build mode).
rm -rf build/test
cmake -S . -B build/test -DCMAKE_C_COMPILER="$CC" -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" \
      -Dsctp_build_programs=0 -Dsctp_werror=0
cmake --build build/test -j"$MAYHEM_JOBS" --target usrsctp
$CC -O2 $COVERAGE_FLAGS -I"$SRC/usrsctplib" "$SRC/mayhem/selftest.c" build/test/usrsctplib/libusrsctp.a \
    -lpthread -o /mayhem/usrsctp_selftest
