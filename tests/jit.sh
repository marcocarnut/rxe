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

# same <pattern> -- compiling and running rxejit's output agrees with rxenum -e,
# and its -n count agrees with the member total. This exercises the whole path:
# codegen, the internal compile, the seeded run, and the count sink.
same() {
    if ! "$RXEJIT" "$1" > "$tmp/jit" 2> "$tmp/e"; then
        printf 'FAIL  %s\n        rxejit: %s\n' "$1" "$(cat "$tmp/e")"
        fail=$((fail + 1)); return
    fi
    "$RXENUM" -e "$1" > "$tmp/ref"
    if ! cmp -s "$tmp/jit" "$tmp/ref"; then
        printf 'FAIL  %s\n        generated output differs from rxenum -e\n' "$1"
        fail=$((fail + 1)); return
    fi
    # The -n count sink must match the number of members.
    n=$("$RXEJIT" -n "$1")
    want=$(wc -l < "$tmp/ref")
    if [ "$n" = "$want" ]; then
        pass=$((pass + 1))
    else
        printf 'FAIL  %s\n        -n counted %s, expected %s\n' "$1" "$n" "$want"
        fail=$((fail + 1))
    fi
}

# emits_compiles <pattern> -- the -S debug output is valid, standalone C.
emits_compiles() {
    if "$RXEJIT" -S "$1" 2>/dev/null | "$CC" -O2 -x c - -o "$tmp/s" 2>"$tmp/e"; then
        pass=$((pass + 1))
    else
        printf 'FAIL  %s\n        -S output did not compile:\n%s\n' "$1" "$(cat "$tmp/e")"
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

# The -S debug output must be valid standalone C.
emits_compiles '[a-z]{3}[0-9]'
emits_compiles 'abc'

# Patterns outside the subset it must decline rather than miscompile.
declines '(a|b)'
declines '[a-z]+'
declines 'a*'
declines '(ab)(?1)'
declines '[:bip39en:]{2}'

printf 'jit: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
