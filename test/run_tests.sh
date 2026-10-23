#!/usr/bin/env bash
# Compile each test case to LLVM IR, run mem2reg, analyze it, and compare the
# status with the "expect:" line in the file. Test programs are never executed.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLANG="${CLANG:-clang}"
OPT="${OPT:-opt}"
ANALYZER="${ANALYZER:-$ROOT/build/taint_analyzer}"
OUT="$ROOT/build/test-ir"
mkdir -p "$OUT"

if [ ! -x "$ANALYZER" ]; then
  echo "analyzer not built: $ANALYZER" >&2
  exit 2
fi

pass=0
fail=0
for src in "$ROOT"/test/cases/T*.c; do
  name="$(basename "$src" .c)"
  expected="$(sed -n 's/.*expect: *\([a-z]*\).*/\1/p' "$src" | head -1)"
  ll="$OUT/$name.ll"
  optll="$OUT/$name.opt.ll"

  if ! "$CLANG" -S -emit-llvm -O0 -g -Xclang -disable-O0-optnone \
       -fno-discard-value-names "$src" -o "$ll" 2>"$OUT/$name.clang.err"; then
    echo "FAIL $name: clang failed"; cat "$OUT/$name.clang.err"; fail=$((fail+1)); continue
  fi
  if ! "$OPT" -S -passes=mem2reg "$ll" -o "$optll" 2>"$OUT/$name.opt.err"; then
    echo "FAIL $name: opt failed"; cat "$OUT/$name.opt.err"; fail=$((fail+1)); continue
  fi

  json="$("$ANALYZER" "$optll")"
  code=$?
  actual="$(printf '%s' "$json" | sed -n 's/^{"status":"\([a-z]*\)".*/\1/p')"

  if [ $code -ne 0 ] || [ -z "$actual" ]; then
    echo "FAIL $name: analyzer error (exit $code): $json"; fail=$((fail+1))
  elif [ "$actual" = "$expected" ]; then
    flow="$(printf '%s' "$json" | grep -o '"label":"[^"]*"' | sed 's/"label":"\(.*\)"/\1/' | paste -sd'>' - | sed 's/>/ -> /g')"
    echo "PASS $name: $actual${flow:+  [$flow]}"; pass=$((pass+1))
  else
    echo "FAIL $name: expected $expected, got $actual"; echo "  $json"; fail=$((fail+1))
  fi
done

echo
echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
