#!/bin/sh
#
# librxe regression suite.
#
# Every case here corresponds either to documented behaviour or to a bug that
# was once real, so a failure means something regressed rather than that a
# check is merely strict.
#
#   sh tests/run.sh            run against ./rxenum
#   RXENUM=/path/to/rxenum ...  run against another build
#
# The suite runs under MALLOC_PERTURB_ so that freshly allocated memory is not
# zero. rxe_new() once left rxe->status uninitialised, which every operation
# read; on a zeroed heap that happens to be RXE_OK, so the bug was invisible
# until malloc started recycling dirty memory. Do not remove this.
#
# 'make test-asan' runs this same suite against a build with AddressSanitizer,
# UndefinedBehaviorSanitizer and LeakSanitizer, with leak detection enabled, so
# a leaked allocation on any path exercised below fails the build.

: "${RXENUM:=./rxenum}"
: "${MALLOC_PERTURB_:=42}"
export MALLOC_PERTURB_

pass=0 fail=0 xfail=0 xpass=0
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

# check <description> <expected> <actual>
check() {
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL  %s\n        expected: %s\n        got:      %s\n' "$1" "$2" "$3"
    fi
}

# xcheck <task> <description> <expected-once-fixed> <actual>
# A known-wrong behaviour we have not fixed yet. Does not fail the suite, but
# shouts if it starts passing so the case can be promoted to a real check.
xcheck() {
    if [ "$3" = "$4" ]; then
        xpass=$((xpass + 1))
        printf 'XPASS %s now behaves correctly -- promote it to check() (%s)\n' "$2" "$1"
    else
        xfail=$((xfail + 1))
    fi
}

# Cardinality, as printed on the first line.
t_count() { check "count $1" "$2" "$("$RXENUM" "$1" 2>&1 | head -1)"; }

# Full enumeration, newline-joined with '/' so empty members stay visible.
t_enum() { check "enum $1" "$2" "$("$RXENUM" -e "$1" 2>&1 | tr '\n' '/')"; }

# Parse error message.
t_error() { check "error $1" "$2" "$("$RXENUM" "$1" 2>&1 | head -1)"; }

# t_opts <expected> <args...> -- arbitrary invocation, output '/'-joined.
t_opts() {
    exp=$1
    shift
    check "rxenum $*" "$exp" "$("$RXENUM" "$@" 2>&1 | tr '\n' '/')"
}

# t_first <expected> <args...> -- first line only, for invocations that also
# print the logarithm lines.
t_first() {
    exp=$1
    shift
    check "rxenum $* (first line)" "$exp" "$("$RXENUM" "$@" 2>&1 | head -1)"
}

# t_rc <expected-status> <args...>
t_rc() {
    exp=$1
    shift
    "$RXENUM" "$@" >/dev/null 2>&1
    check "exit status of rxenum $*" "$exp" "$?"
}

# The two independent ways of reaching an element must agree: counting
# (combinatorial), sequential iteration (rxe_iterate) and random access
# (rxe_seek) are three separate code paths over the same mapping.
t_selfcheck() {
    rx=$1
    "$RXENUM" -e "$rx" >"$tmp/seq" 2>/dev/null
    lines=$(wc -l <"$tmp/seq" | tr -d ' ')
    check "cardinality equals number enumerated: $rx" \
          "$("$RXENUM" -~ "$rx" 2>&1 | head -1)" "$lines"
    [ "$lines" -gt 0 ] || return 0
    step=$((lines / 5 + 1))
    i=0
    while [ "$i" -lt "$lines" ]; do
        check "seek -f $i agrees with iteration: $rx" \
              "$(sed -n "$((i + 1))p" "$tmp/seq")" \
              "$("$RXENUM" -z -f "$i" "$rx" 2>&1)"
        i=$((i + step))
    done
}

echo "== documented examples (README and rxenum.1) =="
t_count '[A-Z]{8}'                                  '208,827,064,576'
t_count '[0-9A-Za-z]{8}'                            '218,340,105,584,896'
t_count '((\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.){3}(?2)' '4,294,967,296'
t_count '(([01]\d\d|2[0-4]\d|25[0-5]|\d{1,2})\.){3}(?2)' '17,944,209,936'
t_opts  'DEAD BEEF /' -z -f 3735928559 '([0-9A-F]{4} ){2}'
check "README approximations" \
      '208,827,064,576 ~ 10^11.3198 ~  2^37.6035' \
      "$("$RXENUM" '[A-Z]{8}' | tr '\n' ' ' | sed 's/ *$//')"
check "roman numeral 3999" 'MMMCMXCIX' \
      "$("$RXENUM" -z 'M{0,3}(C{0,3}|CD|DC{0,3}|CM)(X{0,3}|XL|LX{0,3}|XC)(I{0,3}|IV|VI{0,3}|IX)' -f 3999)"
# The man page shows this as the documented duplicate-generation example.
t_opts '1 /2 a/3 a/4 aa/' -n '(a?){2}'

echo "== #1 uninitialised rxe->status: valid input must not be reported as an error =="
t_count 'abc'   '1'
t_count 'a'     '1'
t_rc 0 'abc'
t_rc 0 '[A-Z]{8}'
t_rc 0 '((\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.){3}(?2)'

echo "== #1 parse errors must report the right message, not a garbage table index =="
t_error 'a*'       'infinite'
t_error 'a+'       'infinite'
t_error 'a{2}{3}'  'nested quantifiers'
t_error '(ab'      'missing parentheses'
t_error 'ab)'      'extraneous parentheses'
t_error '?a'       'nothing before quantifier'
t_error '[abc'     'unterminated character class'
t_error '\1'       'invalid backreference'
t_error '(a\1)'    'infinite'
t_error 'a{3,1}'   'bad repetition parameters'
# Open-ended repetition denotes an infinite set. The RXE_INFINITE assignment
# used to fall through into the bad-parameter check and be overwritten.
t_error 'a{1,}'    'infinite'
t_error 'a{0,}'    'infinite'
t_error 'a{5,}'    'infinite'

echo "== #2 backreferences must enumerate rather than double-free =="
t_enum '(a)\1'              'aa/'
t_enum '([ab])\1'           'aa/bb/'
t_enum '([ab])([cd])\1\2'   'acac/adad/bcbc/bdbd/'
t_enum '(a)(b)(c)\3\2\1'    'abccba/'
t_enum '(([ab])\2)\1'       'aaaa/bbbb/'
t_count '([0-9]{2})-\1'     '100'
t_rc 0 -e '(a)\1'
t_rc 0 -e '([ab])([cd])\1\2'
# (?N) recursion deep-clones, so it is independent of iteration.
t_enum '([ab])(?1)\1'       'aaa/aba/bab/bbb/'

echo "== #3 sets of cardinality zero =="
# A negated class covering all 256 byte values. Note '[]' is NOT an empty
# class -- Perl reads the ']' as a member, so a bare '[]' is unterminated.
t_count '[^\x0-\xFF]'       '0'
t_count 'a[^\x0-\xFF]b'     '0'
t_error '[]'                'unterminated character class'
t_opts  ''      -e 'a[^\x0-\xFF]b'
t_opts  ''      -n 'a[^\x0-\xFF]b'
t_opts  ''      -c 3 'a[^\x0-\xFF]b'
t_rc 0  -e 'a[^\x0-\xFF]b'
t_rc 1  -r 'a[^\x0-\xFF]b'
# An alternation that matches nothing must not contribute a member. This one
# used to emit a string built by indexing a zero-length allocation.
t_count 'xy|a[^\x0-\xFF]b'           '1'
t_enum  'xy|a[^\x0-\xFF]b'           'xy/'
t_enum  'a[^\x0-\xFF]b|xy'           'xy/'
t_enum  'xy|a[^\x0-\xFF]b|zw'        'xy/zw/'
t_enum  '[^\x0-\xFF]|a'              'a/'

echo "== #3 regression guard: a node-less alternation matches the empty string =="
# Cardinality 1, not 0. Treating these as 'matches nothing' would silently
# break every optional construct in the language.
t_enum 'a?'         '/a/'
t_enum '(a)?'       '/a/'
t_enum '(ab)?'      '/ab/'
t_enum 'a{0,2}'     '/a/aa/'
t_enum '(a){0,2}'   '/a/aa/'
t_enum 'M{0,3}'     '/M/MM/MMM/'
t_enum 'a?b?c'      'c/bc/ac/abc/'
t_enum 'a|'         'a//'
t_enum '|a'         '/a/'
t_enum 'a||b'       'a//b/'
t_count 'a{0}'      '1'
t_count '(a){0}'    '1'
# {0} clones nothing, so no clone inherits the subexpression and this node
# holds the only pointer to it. Freeing it here is what 'make test-asan'
# checks; the count is just the visible half.
t_count '(a){0,0}'  '1'
t_count '(ab){0}'   '1'

echo "== #15 '?' replaces the node rather than multiplying it =="
# The quantified node kept its own characters as well as gaining the
# alternation below it, so rxe_iterate stepped both and enumerated the cross
# product. Only 'a?' (one character) and '(ab)?' (none) escaped, so the
# cardinality and the enumeration disagreed for every class of size 2 or more.
t_count '[ab]?'         '3'
t_enum  '[ab]?'         '/a/b/'
t_enum  '[abc]?'        '/a/b/c/'
t_enum  '[ab]?x'        'x/ax/bx/'
t_count '[ab]?[cd]?'    '9'
t_enum  '[ab]?[cd]?'    '/c/d/a/ac/ad/b/bc/bd/'
t_enum  '\d?'           '/0/1/2/3/4/5/6/7/8/9/'
# Caseless doubles a single letter's characters, so it broke 'a?' too.
t_opts  '/a/A/'         -i -e 'a?'
t_opts  '/ab/aB/Ab/AB/' -i -e '(ab)?'

echo "== #10 a backreference names the last repetition, as in Perl =="
t_enum '([ab]){2}\1'        'aaa/abb/baa/bbb/'
t_enum '([ab]){3}\1'        'aaaa/aabb/abaa/abbb/baaa/babb/bbaa/bbbb/'
t_enum '(([ab])(c)){2}\2'   'acaca/acbcb/bcaca/bcbcb/'
t_enum '((a)(b)){2}\2'      'ababa/'
# Groups that are not themselves repeated are unaffected.
t_enum '(x)([ab]){2}\1'     'xaax/xabx/xbax/xbbx/'
t_count '(x)([ab]){1,2}\1'  '6'
# Variable repetition cannot name a single repetition, so it is refused.
t_error '([ab]){1,2}\1' 'backreference into a variably repeated group'
t_error '([ab]){0,2}\1' 'backreference into a variably repeated group'
t_error '(a){2,5}\1'    'backreference into a variably repeated group'
# The reformulation the man page suggests must reproduce Perl's answer.
t_enum '([ab])\1|([ab]){2}\2' 'aa/bb/aaa/abb/baa/bbb/'

echo "== counting, iteration and seeking must agree =="
t_selfcheck '[ab]{3}'
t_selfcheck 'a?b?c'
t_selfcheck '(a|bc)(d|ef)'
t_selfcheck '[a-c]{1,3}'
t_selfcheck 'M{0,3}(C{0,3}|CD|DC{0,3}|CM)'
t_selfcheck '([ab]){2}\1'
t_selfcheck 'xy|a[^\x0-\xFF]b|zw'
t_selfcheck '(a?){2}'
t_selfcheck '[ab]?[cd]?'
t_selfcheck '(?L)[ab][cd]'
t_selfcheck '(?L)[01]{3}'
t_selfcheck '(?L)[a-c]{1,3}'
t_selfcheck '(?L)[ab](?-L:[cd][ef])'
t_selfcheck '(?L)(a|bc)(d|ef)'
t_selfcheck '([0-9A-F]{2} ){2}'

echo "== number formatting =="
t_count '[a-j]{3}'          '1,000'
t_count '[a-j]{6}'          '1,000,000'
t_count '[a-j]{3}|x'        '1,001'
t_count '[a-j]{2}'          '100'
t_count '[a-j]'             '10'
t_first '208.827.064.576' -. '[A-Z]{8}'
t_first '208_827_064_576' -_ '[A-Z]{8}'
t_first '208827064576'    -~ '[A-Z]{8}'
t_first '208,827,064,576' -, '[A-Z]{8}'
# print_grouped once sized its buffer from mpz_size(), which is 0 for zero.
t_count 'a[^\x0-\xFF]b'              '0'
check "-n column alignment holds across a digit boundary" \
      '   999 bmk/ 1,000 bml/' \
      "$("$RXENUM" -n '[a-z]{3}' | sed -n '999p;1000p' | tr '\n' '/')"

echo "== options =="
t_opts 'a/b/'      -e '[ab]'
t_opts '1 a/2 b/'  -n '[ab]'
t_opts '0 a/1 b/'  -zn '[ab]'
t_opts 'aa/ab/ac/' -c 3 -e '[a-z]{2}'
t_opts '5 ae/6 af/7 ag/' -n -f 5 -c 3 '[a-z]{2}'
t_count 'ab'       '1'
t_first '2' -~ '(?i:a)'
t_rc 1 -c 0 '[ab]'
t_rc 1 '[ab]' -f 0

echo "== #5 a caret is special only as a class's first character =="
t_count '[a^b]'     '3'
t_count 'x[a^b]y'   '3'
t_count '[ab^]'     '3'
t_count '[a^]'      '2'
t_count '[\^ab]'    '3'
t_enum  '[a^b]'     '^/a/b/'
# Still an inverter where it belongs, including inverting itself.
t_count '[^ab]'     '254'
t_count '[^^]'      '255'
t_count '[^a-y]'    '231'

echo "== #6 -r seeds from a block of entropy, not one repeatedly-discarded word =="
check "200 draws of [a-z]{4} are not all identical" 'varied' \
      "$(n=$(i=0; while [ $i -lt 200 ]; do "$RXENUM" -r '[a-z]{4}'; i=$((i+1)); done | sort -u | wc -l);
         [ "$n" -gt 1 ] && echo varied || echo identical)"
t_rc 0 -r '[a-z]{6}'
# enumerate() runs once per sample here, and used to leak its accumulators
# on each call. Under 'make test-asan' that is now a failure.
t_rc 0 -r -c 20 '[a-z]{4}'

echo "== #4 inline flag groups =="
# handle_flags returned past the ')', so the caller read a flags-only group as
# a subexpression that never closed and rejected it as 'missing parentheses'.
t_count '(?i)a'         '2'
t_count '(?i)ab'        '4'
t_count '(?i)[a-c]'     '6'
t_count 'a(?i)b'        '2'
t_count '(?i)a(?-i)b'   '2'
t_count '(?-i)a'        '1'
t_count '(?i:a)'        '2'
t_enum  '(?i)a'         'a/A/'
t_enum  '(?i)a(?-i)b'   'ab/Ab/'
# Perl's /s is the flag that makes the dot match everything; the arm used to
# be 'm', so (?s) did nothing and (?m) silently did what (?s) should.
t_count '(?s).'         '256'
t_count '.'             '255'
t_first '256' -s -~ '.'
# /m governs where ^ and $ match, which a set enumerator does not honour, so
# it is accepted and correctly does nothing.
t_count '(?m).'         '255'
# A group that only sets flags must not consume a group number.
t_count '(?i)(a)\1'     '2'
t_count '(?i:x)(a)\1'   '2'

echo "== #13 a ']' in the first member position is a literal =="
t_count '[]]'       '1'
t_count '[^]]'      '255'
t_count '[]a]'      '2'
t_count '[]-a]'     '5'
t_enum  '[]]'       ']/'
t_enum  '[]a]'      ']/a/'
# The class '[a]' followed by a literal ']', not a class holding 'a' and ']'.
t_enum  '[a]]'      'a]/'
# A caret still inverts, and the first member position survives it.
t_error '[]'        'unterminated character class'
t_error '[^]'       'unterminated character class'
t_count '[-]'       '1'
t_count '[^-]'      '255'
t_count '[^^]'      '255'

echo "== #16 group numbering: () captures, (?...) does not =="
# () reached the flags-only branch, because handle_flags returns at once when
# there is no '?', so the group was discarded and took no number.
t_enum  '()'          '/'
t_enum  '()\1'        '/'
t_enum  'a()b'        'ab/'
t_enum  '(a)()\1'     'aa/'
t_enum  '()(a)\2'     'aa/'
# Conversely, every (?...) group is non-capturing and must NOT take a number.
# Registering them shifted every later backreference by one.
t_enum  '(?:a)(b)\1'  'abb/'
t_enum  '(?i:a)(b)\1' 'abb/Abb/'
t_error '(?:a)(b)\2'  'invalid backreference'
t_count '(?i)(a)\1'   '2'
t_count '(?i:x)(a)\1' '2'
# (?N) recursion still resolves against the corrected numbering.
t_count '((\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.){3}(?2)' '4,294,967,296'

echo "== #12 enumeration direction =="
# Right to left is the default: the last position is the least significant
# digit, which is what lets the mapping be read as an ordinary numeral.
t_enum  '[ab][cd]'               'ac/ad/bc/bd/'
t_enum  '[01]{3}'                '000/001/010/011/100/101/110/111/'
# (?L), or -L, makes the first position vary fastest instead.
t_enum  '(?L)[ab][cd]'           'ac/bc/ad/bd/'
t_enum  '(?L)[01]{3}'            '000/100/010/110/001/101/011/111/'
t_opts  'ac/bc/ad/bd/' -L -e '[ab][cd]'
# It reaches subexpressions and repetitions, which build struct rxe of their
# own and so had to be told about it explicitly.
t_enum  '(?L)[ab]([cd][ef])'     'ace/bce/ade/bde/acf/bcf/adf/bdf/'
t_enum  '(?L:[01]{3})'           '000/100/010/110/001/101/011/111/'
t_enum  '(?L)[01]{2}[ab]'        '00a/10a/01a/11a/00b/10b/01b/11b/'
# ...and (?-L:...) puts one subexpression back the other way.
t_enum  '(?L)[ab](?-L:[cd][ef])' 'ace/bce/acf/bcf/ade/bde/adf/bdf/'
t_enum  '(?L:[ab](?-L:[cd][ef]))' 'ace/bce/acf/bcf/ade/bde/adf/bdf/'
t_enum  '(?-L)[ab][cd]'          'ac/ad/bc/bd/'
# Only the order changes; the set and its size do not.
t_count '(?L)[ab][cd]'           '4'
t_count '(?L)[0-9A-F]{4}'        '65,536'
t_count '(?L)((\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.){3}(?2)' '4,294,967,296'
# The default must not move: the documented radix conversion depends on it.
t_opts  'DEAD BEEF /'    -z -f 3735928559 '([0-9A-F]{4} ){2}'
t_opts  'FEEB DAED /' -L -z -f 3735928559 '([0-9A-F]{4} ){2}'

echo "== #18 keyed permutation of the enumeration order =="
# A permutation, not a sample: the same members, each exactly once.
check "permuted run holds exactly the plain set" \
      "$("$RXENUM" -e '[a-z]{2}' | sort | md5sum)" \
      "$("$RXENUM" -k hunter2 -e '[a-z]{2}' | sort | md5sum)"
check "permuted run visits 676 members, all distinct" "676 676" \
      "$("$RXENUM" -k hunter2 -e '[a-z]{2}' | wc -l | tr -d ' ') \
$("$RXENUM" -k hunter2 -e '[a-z]{2}' | sort -u | wc -l | tr -d ' ')"
# The exact order is pinned deliberately. Callers rely on a key reproducing a
# run, so changing the construction is a breaking change and should fail here.
t_opts 'cx/az/by/bz/cy/cz/ay/ax/bx/' -k hunter2 -e '[a-c][x-z]'
t_opts 'cz/cx/bz/ay/ax/by/az/bx/cy/' -k other   -e '[a-c][x-z]'
# Indexing addresses the permuted order, so a run can be resumed.
t_opts 'cx/' -k hunter2 -z -f 0 '[a-c][x-z]'
t_opts 'cy/' -k hunter2 -z -f 4 '[a-c][x-z]'
t_opts 'bx/' -k hunter2 -z -f 8 '[a-c][x-z]'
# Degenerate domains still have to work.
t_opts 'a/'  -k hunter2 -e 'a'
t_opts 'aa/' -k hunter2 -e '(a)\1'
# -k subsumes -r rather than combining with it.
t_rc 1 -r -k x '[ab]'
# It composes with the direction flag: same set, still every member once.
check "(?L) and -k together still cover the set" \
      "$("$RXENUM" -e '(?L)[ab]{3}' | sort | md5sum)" \
      "$("$RXENUM" -k hunter2 -e '(?L)[ab]{3}' | sort | md5sum)"

echo "== known divergences, still open =="

printf '\n%d passed, %d failed' "$pass" "$fail"
[ "$xfail" -gt 0 ] && printf ', %d known-failing' "$xfail"
[ "$xpass" -gt 0 ] && printf ', %d UNEXPECTEDLY FIXED' "$xpass"
printf '\n'
[ "$fail" -eq 0 ] || exit 1
[ "$xpass" -eq 0 ] || exit 1
exit 0
