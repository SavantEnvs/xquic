#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# xquic needs BoringSSL; the Dockerfile builds a pinned copy outside the source tree (air-gapped re-runs).
BSSL_SRC=/opt/boringssl-src
BSSL_BUILD=/opt/boringssl-build
SSL_INC_PATH="$BSSL_SRC/include"
SSL_LIB_PATH="$BSSL_BUILD/libssl.a;$BSSL_BUILD/libcrypto.a"

# Same feature switches for the fuzz build and the test build, so the generated (tracked)
# include/xquic/xqc_configure.h is identical in both.
XQC_CMAKE_ARGS=(
  -DCMAKE_BUILD_TYPE=Release -DDISABLE_WARNINGS=1
  -DSSL_TYPE=boringssl -DSSL_PATH="$BSSL_SRC" -DSSL_INC_PATH="$SSL_INC_PATH" -DSSL_LIB_PATH="$SSL_LIB_PATH"
  -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DXQC_ENABLE_UNLIMITED=1
  -DXQC_ENABLE_COPA=1 -DXQC_COMPAT_DUPLICATE=1 -DXQC_ENABLE_FEC=1 -DXQC_ENABLE_XOR=1
  -DXQC_ENABLE_RSC=1 -DXQC_ENABLE_PKM=1
)

# Four benign UBSan hits fire on every run and would abort every input under halting UBSan, so those
# checks are silenced in the library build only (everything else stays on):
#  - nonnull-attribute: xqc_tls_ctx_register_alpn() does memcpy(buf, NULL, 0) on the first ALPN.
#  - alignment: xqc_palloc_large() returns data[] at offset 12 of its header, so every large pool
#    allocation (e.g. xqc_connection_t) is only 4-byte aligned.
#  - pointer-overflow: NULL + 0 in xqc_stream_recv() (xqc_stream.c:1620) when an H3 stream is read with an
#    empty buffer; clang cannot silence the NULL+0 case separately from real pointer wrap-around.
#  - function: xqc_now() is defined as `()` but called through an `xqc_usec_t (*)(void)` pointer.
LIB_EXTRA_FLAGS="-fno-sanitize=nonnull-attribute,alignment,function,pointer-overflow -fsanitize=fuzzer-no-link"

# No -DCMAKE_C_COMPILER: CMake takes the exported $CC/$CXX itself; passing them as -D makes a re-run see a
# "changed" compiler (cached path is symlink-resolved), which wipes the cache and the SSL_* variables.

# 1) The library, instrumented: ASan+UBSan and DWARF 3 on the code the harnesses fuzz.
cmake -S . -B build/fuzz -GNinja \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $LIB_EXTRA_FLAGS" -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $LIB_EXTRA_FLAGS" \
  "${XQC_CMAKE_ARGS[@]}"
cmake --build build/fuzz --target xquic-static -j"$MAYHEM_JOBS"
LIBXQUIC="$SRC/build/fuzz/libxquic-static.a"

# 2) Harnesses, fuzzer + standalone reproducer each. The harnesses reach into xquic internals
#    (src/...), so they include the repo root as well as include/.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o build/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/standalone_main.o
HARNESSES=(fuzz_transport_params fuzz_frames fuzz_packets)
for h in "${HARNESSES[@]}"; do
  src="$SRC/mayhem/$h.c"
  common=(-I"$SRC" -I"$SRC/include" -I"$SSL_INC_PATH" "$src" build/lsan_off.o "$LIBXQUIC"
          "$BSSL_BUILD/libssl.a" "$BSSL_BUILD/libcrypto.a" -lstdc++ -lm -ldl -lpthread)
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_EXTRA_FLAGS $LIB_FUZZING_ENGINE "${common[@]}" -o "/mayhem/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_EXTRA_FLAGS "${common[@]}" build/standalone_main.o -o "/mayhem/$h-standalone"
done

# 3) The upstream CUnit suite (run_tests) with NORMAL flags, plus the cert/key it loads from cwd.
cmake -S . -B build/tests -GNinja \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DXQC_ENABLE_TESTING=1 "${XQC_CMAKE_ARGS[@]}"
cmake --build build/tests --target run_tests -j"$MAYHEM_JOBS"
if [ ! -f build/tests/server.crt ]; then
  openssl req -newkey rsa:2048 -x509 -nodes -keyout build/tests/server.key -new \
    -out build/tests/server.crt -subj /CN=test.xquic.com
fi
