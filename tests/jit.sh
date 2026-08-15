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

# A small dictionary for the [:name:] tests -- 'red' twice, for the dedup one.
printf 'red\ngreen\nblue\nred\n' > "$tmp/pal.dict"

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
# target set: the same set as filtering rxenum -e through the file. Compared as
# a set (sorted), since across threads the hits come out interleaved, as found.
match() {
    "$RXEJIT" -m "$tmp/targets" "$1" 2>/dev/null | sort > "$tmp/jit"
    "$RXENUM" -e "$1" | grep -Fxf "$tmp/targets" | sort > "$tmp/ref"
    if cmp -s "$tmp/jit" "$tmp/ref"; then
        pass=$((pass + 1))
    else
        printf 'FAIL  match %s\n        -m hit set differs from rxenum -e filtered by the target set\n' "$1"
        fail=$((fail + 1))
    fi
}

# dedup <pattern> -- the -d sink's counts and verdict match the oracle: total
# members from rxenum -e, distinct from sort -u, duplicates their difference.
dedup() {
    out=$("$RXEJIT" -d "$1"); je=$?
    total=$("$RXENUM" -e "$1" | wc -l | tr -d ' ')
    distinct=$("$RXENUM" -e "$1" | sort -u | wc -l | tr -d ' ')
    dups=$((total - distinct))
    got=$(printf '%s' "$out" | grep -oE '[0-9]+' | tr '\n' ' ')
    if [ "$dups" -gt 0 ]; then want="$total $distinct $dups "; want_e=1
    else                        want="$total "; want_e=0; fi
    if [ "$je" = "$want_e" ] && [ "$got" = "$want" ]; then
        pass=$((pass + 1))
    else
        printf 'FAIL  dedup %s\n        got [%s] exit %s, want [%s] exit %s\n' \
               "$1" "$got" "$je" "$want" "$want_e"
        fail=$((fail + 1))
    fi
}

# emits_compiles <args...> -- the -S debug output for these args is valid,
# standalone C (with -pthread, since the threaded sinks link it).
emits_compiles() {
    if "$RXEJIT" -S "$@" 2>/dev/null | "$CC" -O2 -pthread -x c - -o "$tmp/s" 2>"$tmp/e"; then
        pass=$((pass + 1))
    else
        printf 'FAIL  %s\n        -S output did not compile:\n%s\n' "$*" "$(cat "$tmp/e")"
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

# Alternations of equal-length branches: grouped, top-level, embedded, repeated,
# and the duplicate-bearing ones (a dedup sink's reason to exist).
same '(cat|dog)'
same 'cat|dog'
same 'x(a|b)y'
same '(foo|bar)[0-9]{2}'
same '([a-z]|[0-9]){2}'
same '(a|a)'
same '(cat|dog|cat)'
same 'pre(0|1|2)'
same '(a|b)'
same '(ab)(?1)'        # a subroutine call: an independent copy of the group

# Variable-length: uneven-length alternations and empty branches. Same place-
# value order as rxenum -e, but members change width, so they are rebuilt each
# step rather than delta-patched.
same '(cat|hi)'
same '(a|bc)d'
same 'x(a|bc)'
same '(a|)'
same '(ab|a)(b|)'
same '(cat|hi)[0-9]'
same '(a|bc)(d|ef)'

# Bounded variable repeats: finite and place-value ordered, baked as one variable
# wheel by re-parsing the repeat's own span. Uneven widths, same odometer.
same 'a{2,4}'
same '[a-z]{1,2}'
same 'x[0-9]{1,2}y'
same '[0-9]{1,3}'
same 'pre[0-9]{1,2}'
same '(ab){1,2}'
same '(a|aa){1,2}'

# Backreferences: a copy of the named group's bytes, no wheel of their own, via
# g<N>_pos/len locals set as the group is laid. Byte-for-byte rxenum -e.
same '([a-z])\1'
same '(ab|cd)\1'
same '(a)(b)\2\1'
same '([a-z]{2})-\1'
same '(a|b){2}\1'         # repeated group: the backref copies the last iteration
same '([0-9])([a-z])\1\2'

# The match sink: hits (length 3), no hits (length 2, but 'ab'/'q7' are there),
# and a mask disjoint from the targets (empty result both ways).
match '[a-z]{3}'
match '[a-z][0-9]'
match '[a-z]{2}'
match '[0-9]{4}'
match '(a|ab)'          # variable-length: 'a' misses (len 1 vs targets), 'ab' hits

# keycrack <pattern> <plaintext...> -- -H md5 recovers the plaintexts whose MD5
# digests are in the file, printed as digest:plaintext. md5sum builds the
# targets; skipped where it is absent.
keycrack() {
    pat=$1; shift
    : > "$tmp/kh"
    for pt in "$@"; do printf '%s' "$pt" | md5sum | cut -d' ' -f1 >> "$tmp/kh"; done
    got=$("$RXEJIT" -m "$tmp/kh" -H md5 "$pat" 2>/dev/null | sort)
    want=$(for pt in "$@"; do printf '%s:%s\n' "$(printf '%s' "$pt" | md5sum | cut -d' ' -f1)" "$pt"; done | sort)
    if [ "$got" = "$want" ]; then
        pass=$((pass + 1))
    else
        printf 'FAIL  keycrack %s\n        got [%s] want [%s]\n' "$pat" "$got" "$want"
        fail=$((fail + 1))
    fi
}
if command -v md5sum >/dev/null 2>&1; then
    keycrack '[0-9]{4}' 1234 0042 9999
    keycrack '[a-z]{3}' cat dog
    keycrack '(cat|hi)[0-9]' hi7    # variable-length keyspace
else
    printf 'keycrack: skipped, md5sum not found\n'
fi

# The dedup sink: all-distinct masks, and the duplicate-bearing alternations,
# including ones whose repeats fall in different shards under threading.
dedup '[a-z]{3}'
dedup '(a|a)'
dedup '(cat|dog|cat)'
dedup '(a|a)(b|b)'
dedup '(foo|bar|foo)[a-z]{2}'
dedup 'x(a|a|a)y'

# Structural dedup answers a set far too large to enumerate, instantly, from the
# closed form (distinct = product of each wheel's distinct alternatives).
structural() {
    got=$("$RXEJIT" -d "$1"); e=$?
    if [ "$got" = "$2" ] && [ "$e" = "$3" ]; then
        pass=$((pass + 1))
    else
        printf 'FAIL  structural %s\n        got [%s] exit %s, want [%s] exit %s\n' \
               "$1" "$got" "$e" "$2" "$3"
        fail=$((fail + 1))
    fi
}
structural '[a-z]{7}'      '8031810176 members, all distinct' 0
structural '(a|a)[a-z]{6}' '617831552 members, 308915776 distinct, 308915776 duplicates -- NOT distinct' 1

# Variable-length dedup: the alias "ab" from (ab|a)(b|) spans two positions, so
# the closed form cannot see it -- these must take the enumerate-and-hash path.
dedup '(ab|a)(b|)'
dedup '(ab|a)(ba|b)(a|)'
dedup '(cat|hi)(cat|hi)'
dedup 'a{1,2}a{1,2}'    # repeat aliasing: "aa" is a{2} and a{1}a{1}
dedup '(a|aa){1,2}'
dedup '(a|a)\1'         # the alternation's duplicate, seen through the backref

# A variable-count repeat too big to unroll ([a-z]{1,7} is 8 billion) is kept as
# a loop super-wheel instead: an odometer that grows from a to b copies. Cases
# small enough to enumerate are checked byte-for-byte by same(); the body may be
# a class, an equal-length alternation, or a fixed-width dictionary, and fixed
# wheels may sit before and after it. (same() only reaches the loop path when the
# member count clears ALT_CAP = 65536; below that the repeat still bakes.)
same '[a-z]{1,4}'          # 475254 -- bare, the [a-z]{1,7} shape
same '[a-z]{3,4}'          # a >= 1, two lengths
same '[a-z]{0,4}'          # a == 0, includes the empty member
same '[a-z0-9]{1,4}'       # radix 36
same 'x[a-z]{1,4}'         # a leading fixed wheel
same '[a-z]{1,4}!'         # a trailing fixed wheel
same 'ab[a-z]{1,4}yz'      # both, several wide
same '[p-q][a-z]{1,4}[0-9]'
same '[b-c]{1,7}[x-y]'     # the embedded-repeat ordering: bx by cx cy bbx ...
same '(?:[a-z][0-9]){1,3}' # a two-wheel body (m = 2)
same '(ab|cd){1,17}'       # an equal-length alternation body (L = 2)

# The threaded count of a loop repeat is exact and thread-invariant, and the
# seed decode (only exercised when from > 0) lands each shard right.
lr8353=$("$RXEJIT" -n -j 1 '[a-z]{1,7}')
lr8353b=$("$RXEJIT" -n -j 13 '[a-z]{1,7}')
if [ "$lr8353" = "8353082582" ] && [ "$lr8353b" = "8353082582" ]; then
    pass=$((pass + 1))
else
    printf 'FAIL  loop-repeat count: -j1=%s -j13=%s (want 8353082582)\n' "$lr8353" "$lr8353b"
    fail=$((fail + 1))
fi

# A variable-width body (uneven alternation/dict) or a backref across the repeat
# is outside the loop path and must decline, not miscompile.
declines '(a|bc){1,17}'    # uneven-length body, over the cap so it reaches the loop path
declines '[a-z]{1,7}[0-9]{1,7}'   # two big variable-count repeats

# Dictionaries: a [:name:] wheel of the word list, in the -D directory. Write and
# count agree with rxenum -e; dedup finds the word repeated in the list.
dict_ok() {
    "$RXEJIT" -D "$tmp" "$1" 2>/dev/null > "$tmp/jit"
    "$RXENUM" -D "$tmp" -e "$1" 2>/dev/null > "$tmp/ref"
    n=$("$RXEJIT" -D "$tmp" -n "$1" 2>/dev/null)
    if cmp -s "$tmp/jit" "$tmp/ref" && [ "$n" = "$(wc -l < "$tmp/ref")" ]; then
        pass=$((pass + 1))
    else
        printf 'FAIL  dict %s\n' "$1"; fail=$((fail + 1))
    fi
}
dict_ok '[:pal:]'
dict_ok '[:pal:]{2}'
dict_ok '[:pal:]-[0-9]'
d=$("$RXEJIT" -D "$tmp" -d '[:pal:]'); de=$?
if [ "$d" = "4 members, 3 distinct, 1 duplicate -- NOT distinct" ] && [ "$de" = 1 ]; then
    pass=$((pass + 1))
else
    printf 'FAIL  dict dedup: [%s] exit %s\n' "$d" "$de"; fail=$((fail + 1))
fi

# The -S debug output must be valid standalone C, for each sink.
emits_compiles '[a-z]{3}[0-9]'
emits_compiles 'abc'
emits_compiles -d '(a|a)'
emits_compiles -n '[a-z]{3}'
emits_compiles '(a|bc)d'          # variable-length write
emits_compiles -d '(ab|a)(b|)'    # variable-length dedup
emits_compiles -m /dev/null -H md5 '[0-9]{4}'   # keycracking
emits_compiles '([a-z]{2})\1'                   # backreference
emits_compiles -n -p 2 '[a-z]{4}'               # progress reporter (count)
emits_compiles -m /dev/null -H md5 -p 2 '[0-9]{4}'  # progress reporter (keycrack)

# -p must not change the result (timing-only, to stderr).
if [ "$("$RXEJIT" -n -p 1 '[a-z]{3}[0-9]')" = "$("$RXEJIT" -n '[a-z]{3}[0-9]')" ]; then
    pass=$((pass + 1))
else
    printf 'FAIL  -p changed the -n result\n'; fail=$((fail + 1))
fi

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
declines '[a-z]+'
declines 'a*'
declines '[:bip39en:]{2}'

# The GPU backend (-G), only where an OpenCL device is actually present. The
# generated host needs CL headers + libOpenCL to compile and a GPU to run; where
# either is missing (most CI), skip rather than fail. When present, the GPU's
# hit set must be exactly the one the CPU keycrack finds -- the CPU is the oracle
# on the device too. (Probe with a non-empty target: an empty one returns before
# OpenCL is ever touched, so it would not reveal a missing device.)
gpu_avail() {
    "$RXEJIT" -G -S -m /dev/null -H md5 '[a-z]{3}' > "$tmp/g.c" 2>/dev/null || return 1
    "$CC" -O2 "$tmp/g.c" -lOpenCL -o "$tmp/gexe" 2>/dev/null || return 1
    printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' > "$tmp/probe"
    "$tmp/gexe" "$tmp/probe" >/dev/null 2>"$tmp/gerr"
    ! grep -q 'no OpenCL' "$tmp/gerr"
}
if gpu_avail; then
    for w in cat dog fox zzz abcd cdcd; do printf '%s' "$w" | md5sum | cut -d' ' -f1; done > "$tmp/md5t"
    for p in '[a-z]{3}' '[a-f0-9]{4}' '(ab|cd){2}[0-9]'; do
        "$RXEJIT" -G -m "$tmp/md5t" -H md5 "$p" 2>/dev/null | sort > "$tmp/gpu"
        "$RXEJIT"    -m "$tmp/md5t" -H md5 "$p" 2>/dev/null | sort > "$tmp/cpu"
        if cmp -s "$tmp/gpu" "$tmp/cpu"; then pass=$((pass + 1)); else
            printf 'FAIL  -G %s\n        GPU hit set differs from the CPU keycrack\n' "$p"
            fail=$((fail + 1)); fi
    done
    # A variable-length pattern has no fixed-width lane, so -G must decline it.
    if "$RXEJIT" -G -m "$tmp/md5t" -H md5 '[a-z]{1,4}' >/dev/null 2>&1
    then printf 'FAIL  -G should decline a variable-length pattern\n'; fail=$((fail + 1))
    else pass=$((pass + 1)); fi
    printf 'jit: -G tested on the local OpenCL device\n'
else
    printf 'jit: -G skipped (no OpenCL GPU here)\n'
fi

printf 'jit: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
