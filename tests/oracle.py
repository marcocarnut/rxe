#!/usr/bin/env python3
"""Cross-check rxenum against Python's re module.

tests/run.sh pins down behaviour we already know about. This does the
complementary job: for patterns that Python and rxe are supposed to read the
same way, it brute-forces the alphabet and compares the whole set, so a
regression shows up even if nobody thought to write a case for it.

Patterns using constructs Python lacks -- (?N) recursion in particular -- are
deliberately absent, since there would be nothing to compare against.

Duplicates are expected and documented: rxe enumerates the mapping, so
'(a?){2}' legitimately yields "a" twice. Set membership is therefore compared
as a set, while the cardinality is compared against the count including
duplicates.
"""

import itertools
import os
import re
import subprocess
import sys

RXENUM = os.environ.get("RXENUM", "./rxenum")
ENV = dict(os.environ, MALLOC_PERTURB_=os.environ.get("MALLOC_PERTURB_", "42"))

PATTERNS = [
    # plain products and classes
    r"[ab]{3}", r"x[0-9]{2}y", r"[0-9]{1,2}", r"[a-c]{1,3}", r"[ab]",
    # backslash shorthands inside a class, which Python reads the same way as
    # long as the members stay printable -- so \d and \w, not the negated
    # forms whose members include the newline that the line protocol splits on
    r"[\d]", r"[\w]", r"[\d\w]", r"[a-c\d]", r"[\dx]", r"[\w]{2}", r"([\d])\1",
    # alternation
    r"(a|bc)(d|ef)", r"(ab|cd){2}", r"(a|b)(c|d)(e|f)", r"(?:ab|c)d",
    r"a|", r"|a", r"a||b", r"xy|zw",
    # a quantifier after a group, which used to be read as a second one
    # stacked on whatever came before it
    r"a?(x)?", r"(a)?(x)?", r"[ab]?(x)?", r"(a|b)?(c)?d", r"(ab)?(cd)?",
    r"x{1,2}(y|z)?", r"[ab]{2}(c)?",
    # optional and zero-repeat forms
    r"a?", r"(a)?", r"(ab)?", r"a{0,2}", r"(a){0,2}", r"M{0,3}",
    r"a?b?c", r"[ab]?[cd]?", r"(a|b)?c", r"M{0,2}(X|Y)",
    # backreferences
    r"(a)\1", r"([ab])\1", r"([ab])([cd])\1\2", r"(a)(b)(c)\3\2\1",
    r"(([ab])\2)\1", r"([ab]){2}\1", r"([ab]){3}\1", r"(x)([ab]){2}\1",
    r"(([ab])(c)){2}\2", r"([ab])\1|([ab]){2}\2",
    # roman numerals, from the man page
    r"M{0,2}(C{0,2}|CD|DC{0,2}|CM)",
]

# POSIX classes, checked by translating [:name:] to the plain class it stands
# for and comparing the two whole sets. Python's own [[:name:]] is only valid
# inside brackets and means something different, so the translation, not
# Python's parser, is the reference.
POSIX = {
    "[:digit:]": "[0-9]", "[:alpha:]": "[A-Za-z]", "[:alnum:]": "[0-9A-Za-z]",
    "[:upper:]": "[A-Z]", "[:lower:]": "[a-z]", "[:xdigit:]": "[0-9A-Fa-f]",
    "[:word:]": "[0-9A-Za-z_]"
}

# Sets with no largest member. The whole set cannot be compared, so a prefix
# of the enumeration is checked instead: every element must be a member, and
# between them they must cover every member short enough to be reached, which
# is what catches a mapping that skips part of the set rather than merely
# ordering it oddly.
# Sets with no largest member, each with the length up to which coverage is
# checked and how many elements to look at. The whole set cannot be compared,
# so a prefix of the enumeration is checked instead: every element must be a
# member, and between them they must reach every member up to that length.
#
# The prefix needed grows sharply with the number of unbounded quantifiers,
# because the pairing is nested and each level squares the index: reaching all
# of '[ab]*[cd]*[ef]*' up to three characters wants index 7259, where the same
# thing over two dimensions wants 420. That is a property of the diagonal
# walk, not a defect -- everything is still reached in finite time -- but it
# is why the depths below are set per pattern instead of globally.

INFINITE = [
    # one unbounded quantifier
    (r"a*", 6, 200), (r"a+", 6, 200), (r"[ab]*", 5, 200), (r"[ab]+", 5, 200),
    (r"a{3,}", 8, 200), (r"[ab]{2,}", 5, 200),
    (r"xa*y", 6, 200), (r"x[ab]*y", 4, 200), (r"[ab]*c", 5, 200),
    (r"c[ab]*", 5, 200), (r"(ab|c)*", 4, 200), (r"(a|b)+", 5, 200),
    (r"x(a*)y", 6, 200), (r"a|b*", 6, 200), (r"b*|a", 6, 200),
    # two, so the index is one Cantor pairing
    (r"a*b*", 5, 400), (r"[ab]*[cd]*", 3, 600), (r"(a*)(b*)", 5, 400),
    (r"a?b*", 5, 400), (r"a{2,}b{2,}", 6, 400), (r"a*|b*", 5, 400),
    # three, so it is nested twice
    (r"a*b*c*", 4, 800), (r"[ab]*[cd]*[ef]*", 2, 600),
    # a repetition whose body is itself unbounded, which counting by length is
    # what makes reachable at all
    (r"(\d+,)*", 4, 1300), (r"(ab,)*", 6, 200), (r"([ab]+,)*", 4, 400),
    (r"(a*){2}", 6, 200), (r"(a*)?", 6, 200), (r"(a*|b){1,2}", 4, 200),
    (r"a+(x)*", 6, 200), (r"[ab]+(-[ab]+)*", 4, 400),
    # backreferences tie two positions' lengths together, so these keep the
    # diagonal order rather than being refused. Still a bijection onto the
    # whole set, which is what the checks below actually test.
    (r"([ab]+)\1", 4, 200), (r"([0-9]+)-\1", 3, 200), (r"(a)\1a*", 6, 200),
]

# rxenum prints at most this many characters of an element and says nothing
# about having cut it, so anything at the limit is not evidence either way.
MAXSTRLEN = 2048


def run(args):
    p = subprocess.run([RXENUM] + args, capture_output=True, text=True, env=ENV)
    return p.returncode, p.stdout


def enumerate_pattern(pat):
    rc, out = run(["-e", pat])
    if rc != 0:
        return None, f"exited {rc}"
    return out.split("\n")[:-1], None


def brute_force(pat, alphabet, maxlen):
    return {
        "".join(p)
        for n in range(maxlen + 1)
        for p in itertools.product(alphabet, repeat=n)
        if re.fullmatch(pat, "".join(p))
    }


def check_infinite(pat, maxlen, prefix):
    """Returns a list of failure messages for one infinite pattern."""
    bad = []
    rc, out = run(["-e", "-c", str(prefix), pat])
    if rc != 0:
        return [f"FAIL  {pat}: exited {rc}"]
    gen = out.split("\n")[:-1]
    if len(gen) != prefix:
        bad.append(f"FAIL  {pat}: asked for {prefix}, got {len(gen)}")

    # 1. soundness -- everything produced is really a member. Elements at the
    #    print limit were cut short and are not the library's answer.
    wrong = [g for g in gen
             if len(g) < MAXSTRLEN and not re.fullmatch(pat, g)]
    if wrong:
        bad.append(f"FAIL  {pat}: generated non-members {wrong[:5]}")

    # 2. completeness -- nothing short is skipped. A mapping may visit the set
    #    in any order it likes, but it must visit all of it, and an off-by-one
    #    in the block walk or a pairing that is not onto shows up here as a
    #    member that never appears however far you enumerate.
    alphabet = sorted({c for g in gen for c in g})
    if alphabet and len(alphabet) ** (maxlen + 1) <= 200000:
        missing = sorted(brute_force(pat, alphabet, maxlen) - set(gen))
        if missing:
            bad.append(f"FAIL  {pat}: never reached {missing[:5]}"
                       f" (of {len(missing)}) within {prefix}")

    # 3. random access agrees with sequential iteration
    for i in (0, 1, len(gen) // 3, len(gen) - 1):
        rc, out = run(["-z", "-f", str(i), pat])
        if rc != 0 or out.rstrip("\n") != gen[i]:
            bad.append(f"FAIL  {pat}: -f {i} gave {out.rstrip(chr(10))!r},"
                       f" expected {gen[i]!r}")
            break

    # 4. shortest first, where that is claimed. The whole point of counting
    #    by length is that the lengths come out non-decreasing, so this is the
    #    property to check rather than any particular sequence.
    rc, out = run(["-Q", pat])
    if rc == 0 and out.strip() == "shortlex":
        lens = [len(g) for g in gen]
        for i in range(1, len(lens)):
            if lens[i] < lens[i - 1]:
                bad.append(f"FAIL  {pat}: element {i} has length {lens[i]}"
                           f" after one of length {lens[i-1]}")
                break

    # 5. there is no cardinality to report, and it must say so rather than
    #    report the size of the finite part
    rc, out = run(["-~", pat])
    if out.split("\n")[0].strip() != "infinite":
        bad.append(f"FAIL  {pat}: counted {out.split(chr(10))[0]!r},"
                   f" want 'infinite'")
    return bad


# The {{...}} combinatorial quantifier has no counterpart in Python's re, so it
# is checked against itertools instead: the whole set for a small base, plus
# that random access lands where iteration does. Each base is a group of
# distinct alternatives.
CHOOSE = [("(a|b|c|d)", list("abcd")),
          ("(cat|dog|fish)", ["cat", "dog", "fish"]),
          ("[a-e]", list("abcde"))]


def check_choose(bexpr, base):
    """Failure messages for every {{...}} shape over one base."""
    n = len(base)
    cases = []
    for x in range(n + 1):
        cases.append((f"{bexpr}{{{{{x}}}}}",
                      {"".join(c) for c in itertools.combinations(base, x)}))
        cases.append((f"{bexpr}{{{{{x}!}}}}",
                      {"".join(c) for c in itertools.permutations(base, x)}))
    cases.append((f"{bexpr}{{{{1,{n}}}}}",
                  {"".join(c) for x in range(1, n + 1)
                   for c in itertools.combinations(base, x)}))
    cases.append((f"{bexpr}{{{{*}}}}",
                  {"".join(c) for c in itertools.permutations(base, n)}))
    bad = []
    for pat, want in cases:
        gen, err = enumerate_pattern(pat)
        if err:
            bad.append(f"FAIL  {pat}: {err}")
            continue
        # exactly the itertools set, with no repeats (a bijection)
        if set(gen) != want or len(gen) != len(want):
            bad.append(f"FAIL  {pat}: set/count off "
                       f"(got {len(gen)}, want {len(want)})")
            continue
        # seek lands where iteration does
        for i in (0, len(gen) // 2, len(gen) - 1):
            if gen and run(["-z", "-f", str(i), pat])[1].rstrip("\n") != gen[i]:
                bad.append(f"FAIL  {pat}: seek {i} disagrees with iteration")
                break
    return bad


def main():
    failures = 0
    for pat in PATTERNS:
        gen, err = enumerate_pattern(pat)
        if err:
            print(f"FAIL  {pat}: {err}")
            failures += 1
            continue

        # 1. every generated string is a member of the set the regex denotes
        bad = [g for g in gen if not re.fullmatch(pat, g)]
        if bad:
            print(f"FAIL  {pat}: generated non-members {bad[:5]}")
            failures += 1

        # 2. the set is exactly right, not merely sound
        alphabet = sorted({c for g in gen for c in g} | set(re.findall(r"[a-zA-Z0-9]", pat)))
        maxlen = max((len(g) for g in gen), default=0)
        if len(alphabet) ** (maxlen + 1) <= 200000:
            expect = brute_force(pat, alphabet, maxlen)
            if set(gen) != expect:
                missing = sorted(expect - set(gen))[:5]
                extra = sorted(set(gen) - expect)[:5]
                print(f"FAIL  {pat}: missing {missing} extra {extra}")
                failures += 1

        # 3. the reported cardinality matches what was produced
        rc, out = run(["-~", pat])
        count = out.split("\n")[0].strip()
        if rc == 0 and count.isdigit() and int(count) != len(gen):
            print(f"FAIL  {pat}: counted {count}, enumerated {len(gen)}")
            failures += 1

        # 4. random access agrees with sequential iteration
        for i in (0, len(gen) // 2, len(gen) - 1):
            if i < 0:
                continue
            rc, out = run(["-z", "-f", str(i), pat])
            if rc != 0 or out.rstrip("\n") != gen[i]:
                print(f"FAIL  {pat}: -f {i} gave {out.rstrip(chr(10))!r}, expected {gen[i]!r}")
                failures += 1
                break

        # 5. a random member really is a member
        rc, out = run(["-r", pat])
        if rc != 0 or not re.fullmatch(pat, out.rstrip("\n")):
            print(f"FAIL  {pat}: -r produced {out.rstrip(chr(10))!r}, not a member")
            failures += 1

    posix_failures = 0
    for dic, plain in POSIX.items():
        for suffix in ("", "{2}"):
            a = run(["-e", dic + suffix])[1]
            b = run(["-e", plain + suffix])[1]
            if a != b:
                print(f"FAIL  {dic}{suffix} != {plain}{suffix}")
                posix_failures += 1

    inf_failures = 0
    for pat, maxlen, prefix in INFINITE:
        bad = check_infinite(pat, maxlen, prefix)
        for line in bad:
            print(line)
        if bad:
            inf_failures += 1

    choose_failures = 0
    for bexpr, base in CHOOSE:
        bad = check_choose(bexpr, base)
        for line in bad:
            print(line)
        if bad:
            choose_failures += 1

    total = len(PATTERNS) + len(INFINITE) + len(POSIX) * 2 + len(CHOOSE)
    clean = total - failures - inf_failures - posix_failures - choose_failures
    print(f"\noracle: {clean} of {total} patterns clean")
    return 1 if failures or inf_failures or posix_failures or choose_failures else 0


if __name__ == "__main__":
    sys.exit(main())
