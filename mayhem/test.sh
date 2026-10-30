#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the usrsctp functional self-test built by mayhem/build.sh and map its
# PASS/FAIL lines to a CTRF report. Every expected check must report PASS, so a program that
# exits early or prints nothing fails the suite.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

EXPECTED=(
  crc32c-known-answer sockets-created server-bind server-rcvinfo-enabled server-listen client-bind
  association-established client-status-established send-first send-ordered send-fragmented
  first-message-bytes first-message-stream-and-ppid ordered-delivery
  fragmented-message-length fragmented-message-checksum fragmented-message-stream
)

[ -x /mayhem/usrsctp_selftest ] || { echo "missing /mayhem/usrsctp_selftest (build.sh bug)" >&2; emit_ctrf "usrsctp-selftest" 0 1; exit $?; }

out="$(timeout 300 /mayhem/usrsctp_selftest 2>&1)"
echo "$out"

passed=0; failed=0
for name in "${EXPECTED[@]}"; do
  if grep -qx "PASS $name" <<<"$out"; then passed=$((passed+1)); else failed=$((failed+1)); echo "MISSING/FAILED: $name" >&2; fi
done
grep -qx 'DONE failures=0' <<<"$out" || { failed=$((failed+1)); echo "selftest did not finish cleanly" >&2; }
emit_ctrf "usrsctp-selftest" "$passed" "$failed"
