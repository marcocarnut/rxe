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

# A target set for the match sink: some are members of the masks below, some
# are not, some are the wrong length -- only the length-matching members hit.
printf 'cat\ndog\nfox\nbat\nxyz\nzzz\nhello\nq7\nab\n' > "$tmp/targets"

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

# match <pattern> -- the -m sink prints exactly the members that are in the
# target set, in order: the same as filtering rxenum -e through the file.
match() {
    "$RXEJIT" -m "$tmp/targets" "$1" 2>/dev/null > "$tmp/jit"
    "$RXENUM" -e "$1" | grep -Fxf "$tmp/targets" > "$tmp/ref"
    if cmp -s "$tmp/jit" "$tmp/ref"; then
        pass=$((pass + 1))
    else
        printf 'FAIL  match %s\n        -m output differs from rxenum -e filtered by the target set\n' "$1"
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

# The match sink: hits (length 3), no hits (length 2, but 'ab'/'q7' are there),
# and a mask disjoint from the targets (empty result both ways).
match '[a-z]{3}'
match '[a-z][0-9]'
match '[a-z]{2}'
match '[0-9]{4}'

# The -S debug output must be valid standalone C.
emits_compiles '[a-z]{3}[0-9]'
emits_compiles 'abc'

# The threaded count must not depend on how many threads run it.
one=$("$RXEJIT" -n -j 1 '[a-z]{3}[a-z]')
many=$("$RXEJIT" -n -j 8 '[a-z]{3}[a-z]')
if [ "$one" = "$many" ] && [ "$one" = "456976" ]; then
    pass=$((pass + 1))
else
    printf 'FAIL  count thread-invariance: -j1=%s -j8=%s (want 456976)\n' "$one" "$many"
    fail=$((fail + 1))
fi

# Patterns outside the subset it must decline rather than miscompile.
declines '(a|b)'
declines '[a-z]+'
declines 'a*'
declines '(ab)(?1)'
declines '[:bip39en:]{2}'

printf 'jit: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
