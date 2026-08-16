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

# keycrack <alg> <hexcmd> <pattern> <plaintext...> -- -H <alg> recovers the
# plaintexts whose digests are in the file, printed as digest:plaintext. hexcmd
# (md5sum/sha1sum) builds the targets and is the independent oracle; skipped
# where it is absent.
keycrack() {
    alg=$1; hexcmd=$2; pat=$3; shift 3
    : > "$tmp/kh"
    for pt in "$@"; do printf '%s' "$pt" | $hexcmd | cut -d' ' -f1 >> "$tmp/kh"; done
    got=$("$RXEJIT" -m "$tmp/kh" -H "$alg" "$pat" 2>/dev/null | sort)
    want=$(for pt in "$@"; do printf '%s:%s\n' "$(printf '%s' "$pt" | $hexcmd | cut -d' ' -f1)" "$pt"; done | sort)
    if [ "$got" = "$want" ]; then
        pass=$((pass + 1))
    else
        printf 'FAIL  keycrack -H %s %s\n        got [%s] want [%s]\n' "$alg" "$pat" "$got" "$want"
        fail=$((fail + 1))
    fi
}
if command -v md5sum >/dev/null 2>&1; then
    keycrack md5 md5sum '[0-9]{4}' 1234 0042 9999
    keycrack md5 md5sum '[a-z]{3}' cat dog
    keycrack md5 md5sum '(cat|hi)[0-9]' hi7    # variable-length keyspace
else
    printf 'keycrack: skipped, md5sum not found\n'
fi
if command -v sha1sum >/dev/null 2>&1; then
    keycrack sha1 sha1sum '[0-9]{4}' 1234 0042 9999
    keycrack sha1 sha1sum '[a-z]{3}' cat dog
    keycrack sha1 sha1sum '(cat|hi)[0-9]' hi7  # 20-byte digest, variable keyspace
else
    printf 'keycrack: sha1 skipped, sha1sum not found\n'
fi
if command -v sha256sum >/dev/null 2>&1; then
    keycrack sha256 sha256sum '[0-9]{4}' 1234 0042 9999
    keycrack sha256 sha256sum '[a-z]{3}' cat dog  # 32-byte digest
else
    printf 'keycrack: sha256 skipped, sha256sum not found\n'
fi

# NTLM = MD4(UTF-16LE): no standard CLI oracle here, so check against a
# published Windows hash. NTLM("123456") = 32ed87bdb5fdc5e9cba88547376818d4 is a
# well-known vector; [0-9]{6} (1M candidates) must recover it and nothing else.
printf '32ed87bdb5fdc5e9cba88547376818d4\n' > "$tmp/kh"
got=$("$RXEJIT" -m "$tmp/kh" -H ntlm '[0-9]{6}' 2>/dev/null)
if [ "$got" = "32ed87bdb5fdc5e9cba88547376818d4:123456" ]; then pass=$((pass + 1)); else
    printf 'FAIL  keycrack -H ntlm published vector\n        got [%s]\n' "$got"; fail=$((fail + 1)); fi

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

# An ordered permutation (re){{k!}} is a super-wheel like the loop repeat: k of
# the pool's n members in every ordered choice, P(n,k) of them, in rxenum's
# lexicographic-sequence order. same() checks the order and the count byte for
# byte; pre/post fixed wheels and an uneven-width pool are exercised too.
same '(a|b|c){{2!}}'          # P(3,2) = 6, the choose-2 shape
same '(a|b|c){{3!}}'          # every ordering, 3! = 6
same '(a|b|c){{*}}'           # {{*}} is the full permutation
same '(cat|dog|fox){{2!}}'    # multi-byte equal-width members
same '(ab|c|def){{2!}}'       # an uneven-width pool -> variable render
same 'x(a|b|c){{2!}}z'        # pre and post fixed wheels around the choice
same '(a|b|c){{2!}}[0-9]'     # a post odometer, less significant than the choice
same '[a-z]{{2!}}'            # a bare class as the pool, P(26,2) = 650

# The threaded count of a permutation is exact and thread-invariant, and the
# seed decode (from > 0) lands each shard on the right ordering.
pc=$("$RXEJIT" -n -j 1 '(a|b|c|d|e|f|g|h){{5!}}')
pcb=$("$RXEJIT" -n -j 7 '(a|b|c|d|e|f|g|h){{5!}}')
if [ "$pc" = "6720" ] && [ "$pcb" = "6720" ]; then pass=$((pass + 1)); else
    printf 'FAIL  permutation count: -j1=%s -j7=%s (want P(8,5)=6720)\n' "$pc" "$pcb"; fail=$((fail + 1)); fi

# Keycracking "known words, unknown order": recover the ordering whose md5 is the
# target. Independent oracle: md5sum of the true ordering.
if command -v md5sum >/dev/null 2>&1; then
    pwant=$(printf '%s' horsebatterystaple | md5sum | cut -d' ' -f1)
    printf '%s\n' "$pwant" > "$tmp/kh"
    pgot=$("$RXEJIT" -m "$tmp/kh" -H md5 '(battery|horse|staple|correct){{3!}}' 2>/dev/null)
    if [ "$pgot" = "$pwant:horsebatterystaple" ]; then pass=$((pass + 1)); else
        printf 'FAIL  permutation keycrack\n        got [%s]\n' "$pgot"; fail=$((fail + 1)); fi
fi

# Not yet supported: an unordered combination {{k}}, a permutation size range,
# the dedup sink, and the GPU path -- each must decline, not miscompile.
declines '(a|b|c){{2}}'       # unordered combination
declines '(a|b|c){{1,2!}}'    # a size range
if "$RXEJIT" -d '(a|b|c){{2!}}' >/dev/null 2>&1
then printf 'FAIL  -d should decline a permutation\n'; fail=$((fail + 1)); else pass=$((pass + 1)); fi
if "$RXEJIT" -G -m /dev/null -H md5 '(a|b|c){{2!}}' >/dev/null 2>&1
then printf 'FAIL  -G should decline a permutation\n'; fail=$((fail + 1)); else pass=$((pass + 1)); fi

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
    for w in cat dog fox zzz abcd cdcd a to ab ababab; do printf '%s' "$w" | md5sum | cut -d' ' -f1; done > "$tmp/md5t"
    # Fixed masks (one grid) and bare loop repeats (a grid per length): the GPU's
    # hit set must be exactly the CPU keycrack's.
    for p in '[a-z]{3}' '[a-f0-9]{4}' '(ab|cd){2}[0-9]' \
             '[a-z]{1,4}' '[a-z]{2,4}' '[a-z0-9]{1,4}' '(ab|cd){1,17}'; do
        "$RXEJIT" -G -m "$tmp/md5t" -H md5 "$p" 2>/dev/null | sort > "$tmp/gpu"
        "$RXEJIT"    -m "$tmp/md5t" -H md5 "$p" 2>/dev/null | sort > "$tmp/cpu"
        if cmp -s "$tmp/gpu" "$tmp/cpu"; then pass=$((pass + 1)); else
            printf 'FAIL  -G %s\n        GPU hit set differs from the CPU keycrack\n' "$p"
            fail=$((fail + 1)); fi
    done
    # A loop repeat with pre/post or a multi-wheel body is not yet on the GPU, so
    # -G must decline it (and stay on the CPU) rather than miscompile.
    for p in 'x[a-z]{1,4}' '(?:[a-z][0-9]){1,4}'; do
        if "$RXEJIT" -G -m "$tmp/md5t" -H md5 "$p" >/dev/null 2>&1
        then printf 'FAIL  -G should decline %s\n' "$p"; fail=$((fail + 1))
        else pass=$((pass + 1)); fi
    done
    # The generic split: a pattern with structure in the head but a fixed-class
    # tail large enough for the GPU -- rxejit enumerates the head, the GPU sweeps
    # the tail. Uneven alternations, mixed tails, variable-length heads, and dicts
    # all reduce to that, and the GPU's hits must still be the CPU's set.
    printf 'cat\nhello\nfoo\nquux\n' > "$tmp/gw.dict"
    for w in cathello hixyzzy cataa11 foo9x8y7 x1234567 yy0000000 quuxwxyz aa1234567 bb0000000; do
        printf '%s' "$w" | md5sum | cut -d' ' -f1; done >> "$tmp/md5t"
    # A head-side backref is fine too -- rxe renders the copy into the prefix.
    for p in '(cat|hi)[a-z]{5}' '(cat|hi)[a-z]{3}[0-9]{2}' '(x|yy)[0-9]{7}' \
             '[:gw:][a-z]{5}' '(a|b)\1[0-9]{7}'; do
        "$RXEJIT" -G -D "$tmp" -m "$tmp/md5t" -H md5 "$p" 2>/dev/null | sort > "$tmp/gpu"
        "$RXEJIT"    -D "$tmp" -m "$tmp/md5t" -H md5 "$p" 2>/dev/null | sort > "$tmp/cpu"
        if cmp -s "$tmp/gpu" "$tmp/cpu"; then pass=$((pass + 1)); else
            printf 'FAIL  -G (generic) %s\n        GPU hit set differs from CPU\n' "$p"; fail=$((fail + 1)); fi
    done
    # A variable-width dictionary has no fixed tail, so it takes the compacting
    # path: the whole pattern on the GPU, each word's real bytes laid and the
    # running length hashed. The hit set must still be the CPU's. (130 words of
    # length 3-5, so {3} clears the ~1M batch floor.)
    awk 'BEGIN { for (i = 0; i < 130; i++) { n = 3 + i % 3; s = "";
                 for (j = 0; j < n; j++) s = s sprintf("%c", 97 + (i * 7 + j) % 26); print s } }' > "$tmp/vd.dict"
    "$RXEJIT" -G -D "$tmp" -m "$tmp/md5t" -H md5 '[:vd:]{3}' 2>/dev/null | sort > "$tmp/gpu"
    "$RXEJIT"    -D "$tmp" -m "$tmp/md5t" -H md5 '[:vd:]{3}' 2>/dev/null | sort > "$tmp/cpu"
    if cmp -s "$tmp/gpu" "$tmp/cpu"; then pass=$((pass + 1)); else
        printf 'FAIL  -G (compacting) [:vd:]{3}\n        GPU hit set differs from CPU\n'; fail=$((fail + 1)); fi

    # A backref that straddles into the GPU tail, or a set too small to be worth
    # the GPU, must decline (and stay on the CPU) rather than miscompile.
    for p in '([a-z]{3})[0-9]{7}\1' '(cat|hi)[a-z]{2}'; do
        if "$RXEJIT" -G -m "$tmp/md5t" -H md5 "$p" >/dev/null 2>&1
        then printf 'FAIL  -G should decline %s\n' "$p"; fail=$((fail + 1))
        else pass=$((pass + 1)); fi
    done

    # The same kernel paths under a 20-byte digest (sha1) and MD4/UTF-16LE
    # (ntlm): a fixed mask, the generic head/tail split (a head backref, a dict),
    # and the compacting variable-width dict. The CPU keycrack is the oracle on
    # the device for these too. sha1 targets come from sha1sum; ntlm has no CLI
    # oracle here, so a tiny generator built from the runtime header emits them.
    allw="cat dog fox zzz abcd cdcd a to ab ababab cathello hixyzzy cataa11 foo9x8y7 x1234567 yy0000000 quuxwxyz aa1234567 bb0000000"
    have_sha1=0
    if command -v sha1sum >/dev/null 2>&1; then have_sha1=1
        for w in $allw; do printf '%s' "$w" | sha1sum | cut -d' ' -f1; done > "$tmp/sha1t"; fi
    have_sha256=0
    if command -v sha256sum >/dev/null 2>&1; then have_sha256=1
        for w in $allw; do printf '%s' "$w" | sha256sum | cut -d' ' -f1; done > "$tmp/sha256t"; fi
    have_ntlm=0
    cat > "$tmp/ntlmgen.c" <<'EOF'
#include "rxejit_rt.h"
int main(int c, char **v) { unsigned char d[16];
    for (int i = 1; i < c; i++) { rt_ntlm((unsigned char *)v[i], strlen(v[i]), d);
        for (int k = 0; k < 16; k++) printf("%02x", d[k]); putchar('\n'); } return 0; }
EOF
    if "$CC" -O2 -I"$PWD" "$tmp/ntlmgen.c" -o "$tmp/ntlmgen" 2>/dev/null; then have_ntlm=1
        "$tmp/ntlmgen" $allw > "$tmp/ntlmt"; fi
    xcheck() {   # <alg> <targetfile> <pattern>
        "$RXEJIT" -G -D "$tmp" -m "$2" -H "$1" "$3" 2>/dev/null | sort > "$tmp/gpu"
        "$RXEJIT"    -D "$tmp" -m "$2" -H "$1" "$3" 2>/dev/null | sort > "$tmp/cpu"
        if cmp -s "$tmp/gpu" "$tmp/cpu"; then pass=$((pass + 1)); else
            printf 'FAIL  -G -H %s %s\n        GPU hit set differs from CPU\n' "$1" "$3"; fail=$((fail + 1)); fi
    }
    for p in '[a-z]{3}' '(ab|cd){2}[0-9]' '(cat|hi)[a-z]{5}' '(a|b)\1[0-9]{7}' '[:gw:][a-z]{5}' '[:vd:]{3}'; do
        [ "$have_sha1" = 1 ] && xcheck sha1 "$tmp/sha1t" "$p"
        [ "$have_sha256" = 1 ] && xcheck sha256 "$tmp/sha256t" "$p"
        [ "$have_ntlm" = 1 ] && xcheck ntlm "$tmp/ntlmt" "$p"
    done
    # ntlm widens to UTF-16LE, so one GPU block holds only < 28 candidate bytes.
    # (cat|dog){10} is 30 bytes: md5 runs it (30 < 56), ntlm must decline it
    # (60 >= 56) rather than emit a wrong single-block kernel.
    if [ "$have_ntlm" = 1 ]; then
        if "$RXEJIT" -G -m "$tmp/md5t" -H md5 '(cat|dog){10}' >/dev/null 2>&1 &&
           ! "$RXEJIT" -G -m "$tmp/ntlmt" -H ntlm '(cat|dog){10}' >/dev/null 2>&1
        then pass=$((pass + 1))
        else printf 'FAIL  -G width guard: md5 must run and ntlm must decline (cat|dog){10}\n'; fail=$((fail + 1)); fi
    fi

    # The -p occupancy monitor is timing-only (stderr) and must not change the hits.
    "$RXEJIT" -G      -m "$tmp/md5t" -H md5 '[a-z]{1,4}' 2>/dev/null | sort > "$tmp/gp0"
    "$RXEJIT" -G -p 1 -m "$tmp/md5t" -H md5 '[a-z]{1,4}' 2>/dev/null | sort > "$tmp/gp1"
    if cmp -s "$tmp/gp0" "$tmp/gp1"; then pass=$((pass + 1)); else
        printf 'FAIL  -G -p changed the hit set\n'; fail=$((fail + 1)); fi
    printf 'jit: -G tested on the local OpenCL device\n'
else
    printf 'jit: -G skipped (no OpenCL GPU here)\n'
fi

printf 'jit: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
