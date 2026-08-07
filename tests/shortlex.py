#!/usr/bin/env python3
"""Check that infinite sets really do come out shortest member first.

tests/oracle.py already checks soundness and completeness, which a mapping
can satisfy in any order at all. This checks the order itself, and checks it
against something independent: the alphabet is brute-forced, and for each
length the set rxenum produced is compared with the set Python's re accepts.
So a length that is skipped, short by a member, or visited out of turn fails
here even though the set as a whole is right.

Multiplicity is allowed and documented -- '(a*){2}' yields 'aaaa' once per way
of splitting four characters into two runs -- so the per-length comparison is
between sets, and the ordering is checked separately as the lengths being
non-decreasing across the whole run.
"""

import itertools
import os
import re
import subprocess
import sys

RXENUM = os.environ.get("RXENUM", "./rxenum")
CASES = [
    (r"a*", "a", 8, 30), (r"[ab]*", "ab", 6, 400), (r"[ab]+", "ab", 6, 400),
    (r"a*b*", "ab", 6, 400), (r"(ab|c)*", "abc", 5, 400), (r"x[ab]*y", "abxy", 5, 400),
    (r"[ab]*[cd]*", "abcd", 4, 400), (r"(\d+,)*", "0123456789,", 4, 1300),
    (r"(ab,)*", "ab,", 8, 40), (r"a{3,}", "a", 8, 30), (r"(a*){2}", "a", 6, 60),
    (r"[ab]*c", "abc", 5, 400), (r"a?b*", "ab", 6, 400), (r"(a|b)+", "ab", 6, 400),
]
bad = 0
for pat, alpha, maxlen, n_take in CASES:
    out = subprocess.run([RXENUM,"-e","-c",str(n_take),pat],
                         capture_output=True, text=True).stdout.split("\n")[:-1]
    reached = max(len(g) for g in out)
    L = min(maxlen, reached - 1)          # the last length reached may be partial
    ok = True
    # The set at each length must be exactly right. Multiplicity is allowed and
    # documented -- '(a*){2}' yields 'aaaa' once per way of splitting it -- so
    # this compares sets, and the ordering claim is the separate check below.
    for n in range(L+1):
        w = {"".join(t) for t in itertools.product(alpha, repeat=n)
             if re.fullmatch(pat, "".join(t))}
        g = {s2 for s2 in out if len(s2) == n}
        if w != g:
            print(f"FAIL {pat}: length {n} got {sorted(g)[:4]} want {sorted(w)[:4]}")
            ok = False
            break
    lens = [len(s2) for s2 in out]
    if ok and lens != sorted(lens):
        print(f"FAIL {pat}: lengths not non-decreasing")
        ok = False
    if not ok: bad += 1
print(f"shortlex: {len(CASES)-bad} of {len(CASES)} patterns verified against brute force")
sys.exit(1 if bad else 0)
