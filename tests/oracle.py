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
    # alternation
    r"(a|bc)(d|ef)", r"(ab|cd){2}", r"(a|b)(c|d)(e|f)", r"(?:ab|c)d",
    r"a|", r"|a", r"a||b", r"xy|zw",
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

    print(f"\noracle: {len(PATTERNS) - failures} of {len(PATTERNS)} patterns clean")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
