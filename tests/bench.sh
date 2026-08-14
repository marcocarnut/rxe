#!/bin/bash
#
# A speed comparison, not a test: how does rxedup's in-process walk compare to
# enumerating with rxenum and piping into a deduper?
#
#   make bench                 against ./rxenum and ./rxedup
#   RXENUM=... RXEDUP=... ...   against other builds
#
# The engine underneath is the same in both -- rxedup and rxenum -e both walk
# the set with rxe_iterate and rxe_current -- so raw generation is not what
# differs. What rxedup skips is the per-member printf, the pipe (a write and a
# read syscall, and the context switch between them), and a second process
# parsing the lines back. This measures how much that surrounding cost is, and
# it is separate from the compile-to-C win, which speeds the engine itself.
#
# Four rows per pattern let the axes be told apart:
#
#   rxedup                 enumerate + hash + store, in one process
#   rxenum -e | awk        the same streaming-hash dedup, across a pipe
#   rxenum -e | sort -u    the deduper a user actually reaches for
#   rxenum -e >/dev/null   the floor both share: enumerate + format + write
#
# rxedup minus the floor is the cost of hashing over formatting; the piped rows
# minus the floor is the cost of the pipe and the second process.

set -u

# A decimal point, not a comma, so 'time's %R and 'sort -n' agree on what a
# number is -- under a comma locale sort -n reads "0,314" as 0 and the best-of
# pick is meaningless.
export LC_ALL=C

RXENUM=${RXENUM:-./rxenum}
RXEDUP=${RXEDUP:-./rxedup}
REPS=${REPS:-3}

# Best real-time of REPS runs of a shell pipeline, in seconds. The command's own
# output is discarded; only 'time' for the whole pipeline is kept, and the best
# run wins so a scheduling hiccup does not.
runmin() {
    local cmd=$1 i
    for ((i = 0; i < REPS; i++)); do
        { TIMEFORMAT=%R; time eval "$cmd >/dev/null 2>&1"; } 2>&1
    done | sort -n | head -1
}

row() {  # row "label" "command"
    printf '  %-24s %6ss\n' "$1" "$(runmin "$2")"
}

bench() {  # bench "pattern" "rxedup-args"
    local pat=$1 dupargs=${2:-}
    printf '\n%s\n' "$pat"
    # A one-line note on what the set is, from rxedup itself.
    $RXEDUP $dupargs "$pat" 2>&1 | sed 's/^/    -> /'
    row "rxedup"                "$RXEDUP $dupargs '$pat'"
    row "rxenum -e | awk"       "$RXENUM -e '$pat' | awk 'seen[\$0]++'"
    row "rxenum -e | sort -u"   "$RXENUM -e '$pat' | sort -u"
    row "rxenum -e >/dev/null"  "$RXENUM -e '$pat'"
}

echo "rxedup vs. rxenum-and-a-deduper -- best of $REPS runs, real seconds"
echo "rxenum=$RXENUM  rxedup=$RXEDUP"

# Distinct-heavy: 456,976 members, every one distinct. Stresses the hash table
# and, for rxedup, the storage of every member.
bench '[a-z]{4}' '-c 0'

# Duplicate-heavy: ~1.05M members, all "aaaaaaaaaaaaaaaaaaaa". Large total, one
# distinct -- throughput without storage, and the case a deduper collapses hard.
bench '(a|a){20}' '-c 0'

echo
