#!/usr/bin/env bash
# Runs the tests one file at a time. Bun 1.3 on Windows sometimes crashes itself (a segfault, "a bug in Bun, not
# your code") at a different test each run; a file whose run crashed Bun is run again, up to two more times. A test
# that fails is never run again: the step fails as it would under a plain `bun test`.
set -u
failed=()
for f in test/*.test.ts; do
  for try in 1 2 3; do
    out=$(bun test "./$f" 2>&1); code=$?
    printf '%s\n' "$out"
    [ "$code" = 0 ] && break
    if grep -q "Bun has crashed" <<<"$out" && ! grep -q "^(fail)" <<<"$out" && [ "$try" -lt 3 ]; then
      echo "::warning::Bun crashed running $f (try $try); running it again"
      continue
    fi
    failed+=("$f"); break
  done
done
if [ "${#failed[@]}" -gt 0 ]; then echo "::error::failed: ${failed[*]}"; exit 1; fi
