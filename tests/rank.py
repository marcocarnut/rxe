#!/usr/bin/env python3
"""Cross-check rxerank (rank) against rxenum (seek), its inverse.

rxenum turns an index into the member at it; rxerank turns a member back into
the index (or indices) at which it sits. The two must be inverses, and this
pins that down without trusting either in isolation: enumerate the whole set
once with rxenum, which gives the string at every index, then for each distinct
string demand that rxerank return exactly the indices whose string it is.

Because a set may hold a member more than once -- (a|a), (a?){2}, (a|ab)(b|) --
rank is many-valued, and the strong invariant is that the indices it hands back,
gathered over every member, are a permutation of 1..N: each index reached once,
none missed, none invented. That catches an off-by-one in a place value or a
dropped alternation that a single spot-check would sail past.

Only the finite, place-value case is rank's to answer; the infinite, {{k}},
(?~key:) and backreference sets are checked to be *refused*, not ranked.
"""

import os
import subprocess
import sys

RXENUM = os.environ.get("RXENUM", "./rxenum")
RXERANK = os.environ.get("RXERANK", "./rxerank")
ENV = dict(os.environ, MALLOC_PERTURB_=os.environ.get("MALLOC_PERTURB_", "42"))

# Finite sets rank must handle. Duplicates are deliberate: several of these
# spell the same string more than one way, which is the whole point of the
# permutation check.
FINITE = [
    r"[ab]{3}", r"x[0-9]{2}y", r"[0-9]{1,2}", r"[a-c]{1,3}", r"[ab]",
    r"(a|bc)(d|ef)", r"(ab|cd){2}", r"(a|b)(c|d)(e|f)", r"(?:ab|c)d",
    r"a|", r"|a", r"a||b", r"xy|zw",
    r"a?(x)?", r"(a)?(x)?", r"[ab]?(x)?", r"(a|b)?(c)?d", r"(ab)?(cd)?",
    r"x{1,2}(y|z)?", r"[ab]{2}(c)?",
    r"a?", r"(a)?", r"(ab)?", r"a{0,2}", r"M{0,3}",
    r"a?b?c", r"[ab]?[cd]?", r"(a|b)?c", r"M{0,2}(X|Y)",
    # duplicate-bearing sets: the same string at more than one index
    r"(a|a)", r"(a|a)(b|b)", r"(a?){2}", r"(a|ab)(b|)", r"(a|a|a)",
    r"([ab]|[bc])", r"(x|x)(y|y)(z|z)",
    # the empty string reached more than once -- a duplicate with no length to
    # tell the paths apart, so rank must count the paths, not the characters
    r"(|)", r"(||)", r"(|)(|)", r"(a|)(a|)", r"(|a|)", r"(x|)(|y)",
    # nested groups and repeats
    r"((a|b)(c|d)){2}", r"([0-9]{2}){2}", r"(ab){0,3}",
    # repeats whose body can itself be empty, so one string is reached by many
    # repeat counts -- the count must follow the paths, not the characters
    r"(a?){0,4}", r"(a?){3}", r"(a|){2}", r"(ab?){0,2}",
    # keyed shuffles: the key reorders which member sits at which index, so the
    # rank must undo the permutation. The last two shuffle a set that itself
    # holds duplicates, so the remap and the duplication compose.
    r"(?~key:[0-9])", r"(?~secret:[a-c]{2})", r"(?~:M{0,3})",
    r"(?~x:(a|a))", r"(?~k:(a|ab)(b|))",
    # (?L) makes the head the least significant node instead of the tail, so
    # rank must weight the concatenation and the repeat from the other end.
    r"(?L)[a-c][0-9]", r"(?L)(a|b)(c|d)(e|f)", r"(?L)[ab]{3}",
    r"(?L)(ab|cd){2}", r"(?L)(a|a)(b|b)",
    # combinatorial choices: {{k}} unordered (combinadic), {{k!}} ordered
    # (factorial), ranges, and {{*}}. The last two put the choice inside a
    # concatenation and give the body duplicate members, so one string is a
    # valid choice by more than one set of indices -- a duplicate again.
    r"(a|b|c|d){{2}}", r"(a|b|c){{2!}}", r"[a-e]{{3}}",
    r"(a|b|c|d){{1,3}}", r"(a|b|c){{*}}", r"(cat|dog|fish){{2!}}",
    r"x(a|b|c){{2}}y", r"(a|a|b){{2}}",
    # backreferences: a \1 must equal what its group matched on the same path,
    # which adds no index of its own. Includes a repeated group (bound to its
    # last iteration), nested groups, a backref across an alternation, and a
    # group with duplicate branches so one string is reached more than one way.
    r"(a)\1", r"([ab])\1", r"([ab])([cd])\1\2", r"(a)(b)(c)\3\2\1",
    r"(([ab])\2)\1", r"([ab]){2}\1", r"([ab]){3}\1", r"(x)([ab]){2}\1",
    r"([ab])\1|([ab]){2}\2", r"(([ab])(c)){2}\2", r"(a|a)\1", r"(\d{2})-\1",
    # roman numerals, finite
    r"M{0,2}(C{0,2}|CD|DC{0,2}|CM)",
    # policy composition {{n,m!floors}}: a length range over the union of the
    # branches with a floor per branch (a password policy). A '+' soaker (order
    # only), a policy inside a concatenation (place value), one-of-each, and
    # overlapping branches so a character reaches more than one branch -- a
    # duplicate, so rank must return every index the string sits at.
    r"([01]|[ab]){{3!1,0}}", r"([01]|[AB]|[abc]){{4!1,1,2}}",
    r"([01]|[ab]){{2,3!1,0}}", r"([01]|[ab]){{3!1,+}}",
    r"(a|b|c){{3!1,1,1}}", r"x([01]|[ab]){{2!1,0}}y",
    r"([ab]|[bc]){{2!1,0}}",
]

# Sets rank is not meant to answer yet: it must refuse them by name, never
# guess. Each entry is a pattern and the substring its reason should contain.
# Infinite sets rank now handles: shortlex order, fixed-length repeat body. The
# check is a round-trip over a prefix of the enumeration -- every index must be
# among those its string ranks to.
INFINITE = [
    r"a*", r"a+", r"[ab]*", r"[ab]+", r"\d+", r"a{3,}", r"[ab]{2,}",
    r"xa*y", r"x[ab]*y", r"[ab]*c", r"c[ab]*", r"(ab)*", r"(abc)+",
    r"a*b*", r"a*b*c*", r"[ab]*[cd]*", r"(a|b)+", r"a|b*", r"b*|a",
    r"\d{2,}", r"(a|b)*", r"x\d+y", r"(ab,)*",
]

# Sets rank still refuses: a variable-length repeat body, a backreference that
# keeps an infinite set in diagonal order, or left-to-right ordering.
REFUSE = [
    (r"(\d+,)*", "variable-length"), (r"(a|bb)*", "variable-length"),
    (r"(?L)a*", "variable-length"),
    (r"([ab]+)\1", "diagonal"), (r"([0-9]+)-\1", "diagonal"),
]

# A handful of strings that are not members, to confirm a clean miss.
NONMEMBERS = [
    (r"[a-c][0-9]", ["zz", "a", "aa", "d5", ""]),
    (r"(ab|cd)", ["a", "abcd", "ac", ""]),
    (r"a{0,2}", ["aaa", "b"]),
]


def run(binary, args):
    p = subprocess.run([binary] + args, capture_output=True, text=True, env=ENV)
    return p.returncode, p.stdout, p.stderr


def enumerate_set(pat):
    rc, out, _ = run(RXENUM, ["-e", pat])
    if rc != 0:
        return None
    return out.split("\n")[:-1]      # member at 1-based index k is line k-1


def ranks_of(pat, s):
    """Every index (1-based) rxerank -a returns for string s, sorted."""
    rc, out, _ = run(RXERANK, ["-a", pat, s])
    if rc not in (0, 1):
        return None
    return sorted(int(x) for x in out.split("\n") if x != "")


def check_finite(pat):
    bad = []
    gen = enumerate_set(pat)
    if gen is None:
        return [f"FAIL  {pat}: rxenum -e failed"]
    n = len(gen)

    # positions[value] = the 1-based indices whose member is exactly value
    positions = {}
    for k, v in enumerate(gen, start=1):
        positions.setdefault(v, []).append(k)

    seen = []
    for v, want in positions.items():
        got = ranks_of(pat, v)
        if got != sorted(want):
            bad.append(f"FAIL  {pat}: rank -a {v!r} = {got}, want {sorted(want)}")
            continue
        seen += got
        # count agrees with the list
        rc, out, _ = run(RXERANK, ["-c", pat, v])
        if rc not in (0, 1) or out.strip() != str(len(want)):
            bad.append(f"FAIL  {pat}: rank -c {v!r} = {out.strip()!r},"
                       f" want {len(want)}")
        # the first index is the least of them
        rc, out, _ = run(RXERANK, [pat, v])
        if rc != 0 or out.strip() != str(min(want)):
            bad.append(f"FAIL  {pat}: rank {v!r} = {out.strip()!r},"
                       f" want {min(want)}")

    # the indices, over every member, are exactly a permutation of 1..n
    if sorted(seen) != list(range(1, n + 1)):
        bad.append(f"FAIL  {pat}: ranks are not a permutation of 1..{n}")
    return bad


def check_infinite(pat, n=48):
    """Round-trip a prefix of an infinite set: seek i, rank it, i must be there."""
    rc, out, _ = run(RXENUM, ["-z", "-e", "-c", str(n), pat])
    if rc != 0:
        return [f"FAIL  {pat}: rxenum -e failed"]
    gen = out.split("\n")[:-1]
    bad = []
    for i, s in enumerate(gen):
        rc, out, _ = run(RXERANK, ["-z", "-a", pat, s])
        if rc not in (0, 1):
            bad.append(f"FAIL  {pat}: rank -a {s!r} exit {rc}")
            break
        ranks = [int(x) for x in out.split("\n") if x != ""]
        if i not in ranks:
            bad.append(f"FAIL  {pat}: seek {i} = {s!r}, but rank gives {ranks}")
            break
    return bad


def check_refuse(pat, want):
    rc, out, err = run(RXERANK, [pat, "x"])
    if rc != 2:
        return [f"FAIL  {pat}: expected refusal (exit 2), got exit {rc}"]
    if want not in err:
        return [f"FAIL  {pat}: reason {err.strip()!r} lacks {want!r}"]
    return []


def check_nonmembers(pat, strings):
    bad = []
    for s in strings:
        rc, out, _ = run(RXERANK, [pat, s])
        if rc != 1 or out.strip() != "":
            bad.append(f"FAIL  {pat}: {s!r} should be a non-member,"
                       f" got exit {rc} out {out.strip()!r}")
        rc, out, _ = run(RXERANK, ["-c", pat, s])
        if out.strip() != "0":
            bad.append(f"FAIL  {pat}: count {s!r} = {out.strip()!r}, want 0")
    return bad


def main():
    failures = 0
    for pat in FINITE:
        bad = check_finite(pat)
        for line in bad:
            print(line)
        failures += bool(bad)
    for pat in INFINITE:
        bad = check_infinite(pat)
        for line in bad:
            print(line)
        failures += bool(bad)
    for pat, want in REFUSE:
        bad = check_refuse(pat, want)
        for line in bad:
            print(line)
        failures += bool(bad)
    for pat, strings in NONMEMBERS:
        bad = check_nonmembers(pat, strings)
        for line in bad:
            print(line)
        failures += bool(bad)

    total = len(FINITE) + len(INFINITE) + len(REFUSE) + len(NONMEMBERS)
    print(f"\nrank: {total - failures} of {total} patterns clean")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
