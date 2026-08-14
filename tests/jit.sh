#!/bin/sh
#
# rxejit correctness: the C it generates must enumerate a mask in exactly the
# order and content rxenum -e does. For each pattern, compile rxejit's output
# and diff it against the interpreter. A divergence means the codegen and the
# engine disagree -- the one thing the JIT must never do.
#
#   sh tests/jit.sh
#   RXENUM=... RXEJIT=... CC=... sh tests/jit.sh

: "${RXENUM:=./rxenum}"
: "${RXEJIT:=./rxejit}"
: "${CC:=cc}"

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
pass=0 fail=0

# same <pattern> -- the generated enumerator agrees with rxenum -e
same() {
    if ! "$RXEJIT" "$1" > "$tmp/g.c" 2> "$tmp/e"; then
        printf 'FAIL  %s\n        rxejit declined: %s\n' "$1" "$(cat "$tmp/e")"
        fail=$((fail + 1)); return
    fi
    if ! "$CC" -O2 "$tmp/g.c" -o "$tmp/g" 2> "$tmp/e"; then
        printf 'FAIL  %s\n        generated C did not compile:\n%s\n' "$1" "$(cat "$tmp/e")"
        fail=$((fail + 1)); return
    fi
    "$tmp/g" > "$tmp/jit"
    "$RXENUM" -e "$1" > "$tmp/ref"
    if cmp -s "$tmp/jit" "$tmp/ref"; then
        pass=$((pass + 1))
    else
        printf 'FAIL  %s\n        generated output differs from rxenum -e\n' "$1"
        fail=$((fail + 1))
    fi
}

# declines <pattern> -- rxejit refuses a pattern outside the mask subset
declines() {
    if "$RXEJIT" "$1" > /dev/null 2>&1; then
        printf 'FAIL  %s\n        expected rxejit to decline it, but it did not\n' "$1"
        fail=$((fail + 1))
    else
        pass=$((pass + 1))
    fi
}

# Masks it must reproduce exactly.
same 'a'
same 'abc'
same 'X9z'
same '[ab][cd]'
same '[a-z]{3}'
same '\d{4}'
same '[a-z]{2}[0-9]{2}'
same 'q[0-9]w[a-f]'
same '[A-Fa-f0-9]{2}'
same '[0-9]'

# Patterns outside the subset it must decline rather than miscompile.
declines '(a|b)'
declines '[a-z]+'
declines 'a*'
declines '(ab)(?1)'
declines '[:bip39en:]{2}'

printf 'jit: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
