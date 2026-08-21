# rxe38 — a BIP38 (no-EC-multiply) passphrase cracker

**Status: CPU implementation COMPLETE.** All five milestones built and passing
on branch `rxe38` (`rxe38.c`, one file). `make rxe38` builds it; `make
bip38-test` runs the self-tests. The whole cryptographic core is diff-exact
against `bip38_oracle.py`, and the CLI cracks the BIP38 spec vectors end to end
(recovering passphrase + WIF) at ~4–5 candidates/s/core — the scrypt-bound
regime the plan anticipated. GPU is the open next step (a separate reassessment;
see the note at the end).

Milestone status:
- [x] 1. base58check decode + BIP38 parse — parse byte-exact vs oracle (4/4).
- [x] 2. scrypt(16384,8,8,64) — 3 RFC 7914 vectors + oracle dh1||dh2 (`--test-scrypt`).
- [x] 3. AES-256 ECB decrypt + XOR — FIPS-197 + oracle privkeys (`--test-priv`).
- [x] 4. secp256k1(gmp)+RIPEMD-160+base58 — full verify, all 4 vectors + a
      wrong-passphrase negative (`--test-verify`, the correctness GATE).
- [x] 5. CLI: librxe `rxe_foreach` enumeration, pthreads shard (rxe_deep_clone
      per thread, shared first-hit stop), `-j`/`-c`/`-p` (rate+ETA monitor).

The original plan, kept below for reference.

## What it is

A **standalone** command-line tool `rxe38`, sitting alongside rxenum/rxejit/
rxedot/rxerank/rxedup, that cracks a BIP38-encrypted Bitcoin private key by
trying passphrases from a regex-described keyspace.

- `rxe38 <6P...key> '<passphrase-regex>'` → enumerate the regex, BIP38-verify
  each candidate, print the passphrase (and WIF) on a hit.
- It **links `librxe.a`** and uses the library's enumerator (`rxe_foreach` /
  the rows API — the same walk rxenum uses) to generate candidates. It does
  **NOT** use rxejit's JIT/odometer: candidate generation is free next to
  scrypt, so the compiler buys nothing here. Multithread with pthreads (shard
  the enumeration like rxejit's -j sinks), reuse `rt_sha256` (SHA-NI) from
  rxejit_rt.h for the PBKDF2/HMAC-SHA256, and link `-lgmp` for the EC field math.

## Why separate, and the cost regime (agreed with Kiko)

BIP38 is deliberately expensive: scrypt(N=16384, r=8, p=8) is memory-hard
(~16 MB working set) AND each candidate needs a secp256k1 point-multiply to
verify. Throughput is **candidates/second** — tens/sec/core on CPU, kH/s even on
a GPU (Kiko's expectation; scrypt is anti-GPU by design). So:
- rxe's value here is the **regex keyspace** (you can only crack BIP38 with a
  constrained, structured guess space — a half-remembered passphrase). That is
  exactly what librxe expresses.
- The incremental-odometer work is **irrelevant** here (generation ≪ scrypt).
- First pass is **CPU only**; GPU is a later reassessment, not committed.

## Scope (locked)

- **No-EC-multiply mode ONLY** (keys `6PR.../6PY...`, base58 prefix `0x0142`).
  Defer EC-multiply mode (`6Pf.../6Pg...`, prefix `0x0143`, intermediate/
  confirmation codes — a different, two-scrypt pipeline).
- **secp256k1: vendor a compact impl, built on gmp** (rxe already links gmp).
  We only need pubkey derivation (privkey·G), not signing — ~250 lines: field
  arithmetic mod p, the group law, double-and-add scalar multiply. gmp is the
  CPU-phase choice; a fixed u256 would replace it only if we ever revisit GPU.

## IMPORTANT clarification — "no EC multiply" does NOT mean "skip the address check"

"EC multiply" is a property of how the key was **encrypted**, not our verify.
Even in no-EC-multiply mode we MUST derive the address and check the 4-byte
`addresshash` — it is the ONLY verifier in the key (no other checksum on the
privkey). So per candidate we still do privkey → pubkey (**secp256k1 multiply,
mandatory**) → hash160 → base58 address → SHA256d[:4] == addresshash. Without it
every passphrase would "succeed". secp256k1 is load-bearing.

## The pipeline (no-EC-multiply) — see bip38_oracle.py for the exact bytes

```
base58check-decode(6P...)  -> 39 bytes: [0x01 0x42] flag(1) addrhash(4) enc1(16) enc2(16)
  flag & 0x20  => compressed pubkey
per candidate passphrase (UTF-8; BIP38 says NFC-normalize — matters only for non-ASCII):
  d   = scrypt(pass, salt=addrhash, N=16384, r=8, p=8, dkLen=64)
  dh1 = d[0:32];  dh2 = d[32:64]                      # dh2 is the AES-256 key
  dec1 = AES256_ECB_decrypt(enc1, dh2);  dec2 = AES256_ECB_decrypt(enc2, dh2)
  priv = (dec1 XOR dh1[0:16]) || (dec2 XOR dh1[16:32])   # 32-byte private key
  VERIFY: SHA256d( base58check_address(priv, compressed) )[0:4] == addrhash
```

## C-port milestones (build standalone harness FIRST, diff every step vs the oracle)

1. **base58check decode + BIP38 parse** → flag/addrhash/enc1/enc2. Check vs oracle.
2. **scrypt(16384,8,8,64)** = PBKDF2-HMAC-SHA256 + Salsa20/8 + BlockMix + ROMix.
   Check vs RFC 7914 scrypt vectors AND the oracle's `dh1||dh2` for a spec key.
   (Reuse rt_sha256 for HMAC; Salsa20/8 + the 16 MB ROMix scratchpad are new.)
3. **AES-256 ECB decrypt** (decrypt only, 2 blocks) + XOR → privkey.
   Check vs FIPS-197 AES-256 vector AND the oracle's recovered privkey/WIF.
4. **secp256k1 (on gmp) + RIPEMD-160 + base58** → address → SHA256d[:4].
   Full end-to-end verify on all 4 spec vectors == the correctness GATE.
5. **Wire the CLI `rxe38`**: link librxe, enumerate the regex (foreach/rows),
   pthreads shard, per-candidate BIP38 check, early-exit on hit, `-p` progress
   (reuse the H/s + eta formatters). Crack a self-made key over a regex keyspace.

Then measure the real rate and decide whether GPU is worth it (separate effort).

## Test vectors (BIP38 spec, no-EC-multiply) — the four in bip38_oracle.py

| passphrase | encrypted key | compressed | addrhash | WIF |
|---|---|---|---|---|
| TestingOneTwoThree | 6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg | no  | e957a24a | 5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR |
| Satoshi            | 6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq | no  | 572e117e | 5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5 |
| TestingOneTwoThree | 6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo | yes | 43be4179 | L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP |
| Satoshi            | 6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7 | yes | 26e017d2 | KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7 |

## Building blocks already in the tree

- `rxejit_rt.h`: `rt_sha256` (SHA-NI accelerated + scalar fallback) — reuse for HMAC-SHA256.
- rxe links **gmp** already (Makefile `-lgmp`) — use it for the secp256k1 field math.
- `librxe.a` + `rxe.h`: the enumerator. `rxe_foreach` walks members; rxenum.c / rxedup.c
  show the shard-and-thread pattern to copy.
- The oracle's Python deps on the dev box: `hashlib.scrypt`, `cryptography` (AES),
  `ecdsa`, `base58`, `hashlib.new('ripemd160')` (worked here; may vary by openssl).
