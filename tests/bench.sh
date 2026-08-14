#!/bin/bash
#
# A speed comparison, not a test. Two questions:
#
#   1. Single-threaded, does rxedup beat enumerating with rxenum and piping into
#      a deduper? The engine underneath is the same -- both walk the set with
#      rxe_iterate and rxe_current -- so what rxedup saves is only the per-member
#      printf, the pipe, and a second process reading the lines back. The
#      benchmark's earlier finding was that this is nearly nothing: the shared
#      engine is almost the whole cost, and awk's hash over a pipe is very fast.
#
#   2. Threaded, how far does rxedup pull ahead? This is the thing rxenum cannot
#      do. rxe_foreach shards on the index range, so -j hands each core a slice.
#
# Runs are sized to take about ten seconds single-threaded: below that, OS
# scheduling noise swamps the numbers. REPS best-of runs guard what noise is
# left. Set REPS, or point RXENUM/RXEDUP at other builds.
#
#   make bench                 against ./rxenum and ./rxedup
#   REPS=3 make bench          more runs per row
#
# Note: the distinct-heavy pattern stores every member, ~2 GiB here. The
# duplicate-heavy one stores one, so it is where thread scaling shows cleanest.

set -u
export LC_ALL=C                 # so 'time' %R and 'sort -n' agree on the decimal point

RXENUM=${RXENUM:-./rxenum}
RXEDUP=${RXEDUP:-./rxedup}
REPS=${REPS:-2}
NP=$(nproc 2>/dev/null || echo 4)

# Best real-time of REPS runs of a pipeline, in seconds; the command's own output
# is discarded and the best run wins.
runmin() {
    local cmd=$1 i
    for ((i = 0; i < REPS; i++)); do
        { TIMEFORMAT=%R; time eval "$cmd >/dev/null 2>&1"; } 2>&1
    done | sort -n | head -1
}

row() { printf '  %-26s %7ss\n' "$1" "$(runmin "$2")"; }

echo "rxedup speed -- best of $REPS runs, real seconds, $NP CPUs"
echo "rxenum=$RXENUM  rxedup=$RXEDUP"

# ---- 1. single-threaded: rxedup vs. a deduped pipe -------------------------
# (a|a){22}: 4.19M members, all identical. Large total, one distinct, so this is
# generation-and-hashing throughput with no storage to muddy it.
echo
echo "(a|a){22} -- 4.19M members, 1 distinct (single-threaded)"
row "rxedup -j1"             "$RXEDUP -j1 -c 0 '(a|a){22}'"
row "rxenum -e | awk"        "$RXENUM -e '(a|a){22}' | awk 'seen[\$0]++'"
row "rxenum -e | sort -u"    "$RXENUM -e '(a|a){22}' | sort -u"
row "rxenum -e >/dev/null"   "$RXENUM -e '(a|a){22}'"

# ---- 2. thread scaling -----------------------------------------------------
# The same throughput-bound set, now across cores. The merge is trivial (one
# distinct), so this is close to how far the walk itself parallelises.
echo
echo "(a|a){22} -- thread scaling (duplicate-heavy, trivial merge)"
for j in 1 2 4 8 "$NP"; do row "rxedup -j$j" "$RXEDUP -j$j -c 0 '(a|a){22}'"; done

# A distinct-heavy set for contrast: 11.88M members, every one stored and then
# merged serially, so threading helps less and memory bandwidth caps it.
echo
echo "[a-z]{5} -- thread scaling (distinct-heavy, ~2 GiB, serial merge)"
for j in 1 "$NP"; do row "rxedup -j$j" "$RXEDUP -j$j -c 0 '[a-z]{5}'"; done

echo
