#!/bin/sh
# Golden-output guard for rxedot. rxedot draws the parse tree as DOT; it has no
# other test, so this pins its exact output across the patterns and flags that
# exercise every branch of the traversal. Run it before and after any change to
# rxedot -- above all the planned refactor that lifts the tree-walk into a
# librxe rxe_graph and leaves rxedot as just the DOT backend: the output must
# not move a byte.
#
#   sh tests/rxedot.sh            check current rxedot against tests/rxedot-golden
#   sh tests/rxedot.sh --update   regenerate the golden files (after an
#                                 intentional change, reviewed by eye)
#
# The .dot files and this list are the fixture; keep them in step.

RXEDOT=${RXEDOT:-./rxedot}
DIR=tests/rxedot-golden
mode=${1:-check}

# patterns chosen to hit: classes, repeats, alternations, subroutines,
# backrefs, nesting, combinatorial, infinite/shortlex, shuffle, and the roman
# numerals from the man page.
set -- \
  '[a-z]{4}' \
  '\d{4}-\d{2}-\d{2}' \
  '(cat|dog|fish)' \
  '(\d{3})(?1)' \
  '([ab])\1' \
  '((a|b)(c|d)){2}' \
  '([2-9TJQKA][SHDC]){{5}}' \
  'a*b*' \
  '(?~k:[0-9])' \
  'M{0,2}(C{0,2}|CD|DC{0,2}|CM)'

FLAGS='|-c|-e|-w|-u 3|-t|-f 5'

mkdir -p "$DIR"
fail=0
n=0
for pat in "$@"; do
    OLDIFS=$IFS; IFS='|'
    for fl in $FLAGS; do
        IFS=$OLDIFS
        key=$(printf '%s' "$pat$fl" | md5sum | cut -c1-12)
        gold="$DIR/$key.dot"
        n=$((n + 1))
        if [ "$mode" = "--update" ]; then
            $RXEDOT $fl "$pat" > "$gold" 2>&1
        else
            got=$($RXEDOT $fl "$pat" 2>&1)
            if [ ! -f "$gold" ]; then
                echo "MISSING golden for: rxedot $fl '$pat' (run --update)"
                fail=$((fail + 1))
            elif [ "$got" != "$(cat "$gold")" ]; then
                echo "DIFF: rxedot $fl '$pat'"
                fail=$((fail + 1))
            fi
        fi
        OLDIFS=$IFS; IFS='|'
    done
    IFS=$OLDIFS
done

if [ "$mode" = "--update" ]; then
    echo "rxedot: regenerated $n golden outputs in $DIR"
elif [ "$fail" -eq 0 ]; then
    echo "rxedot: $n of $n outputs match golden"
else
    echo "rxedot: $fail of $n outputs differ"
    exit 1
fi
