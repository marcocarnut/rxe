/*
 * rxe38 -- crack a BIP38-encrypted Bitcoin private key (no-EC-multiply mode)
 * by trying passphrases drawn from a regex-described keyspace.
 *
 * Built in milestones, each diffed against bip38/bip38_oracle.py (the
 * differential ground truth). This file grows one milestone at a time:
 *
 *   1. base58check decode + BIP38 parse            <-- current
 *   2. scrypt(16384,8,8,64)  = PBKDF2/HMAC-SHA256 + Salsa20/8 + BlockMix + ROMix
 *   3. AES-256 ECB decrypt (2 blocks) + XOR        -> candidate private key
 *   4. secp256k1 (gmp) + RIPEMD-160 + base58       -> address -> SHA256d[:4]
 *   5. wire the CLI: link librxe, enumerate the regex, pthreads, -p progress
 *
 * SHA-256 is reused from the rxejit runtime (SHA-NI accelerated, scalar
 * fallback); everything else here is hand-written for this tool.
 *
 *          (C) 2026 Marco "Kiko" Carnut <kiko at postcogito dot org>, GPLv2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* rt_sha256(msg, len, out[32]) -- the only piece we borrow from rxejit. */
#include "rxejit_rt.h"

/* ---- SHA-256 helpers ---------------------------------------------------- */

/* Double SHA-256, as Bitcoin checksums are computed. */
static void sha256d(const unsigned char *msg, unsigned long len,
                    unsigned char out[32])
{
    unsigned char t[32];
    rt_sha256(msg, len, t);
    rt_sha256(t, 32, out);
}

/* ---- base58 / base58check ---------------------------------------------- */

static const char B58[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* index of a base58 digit, or -1 if not one. */
static int b58val(int c)
{
    const char *p = strchr(B58, c);
    return (p && c) ? (int)(p - B58) : -1;
}

/* Decode a base58 string into raw bytes. Writes at most *outlen bytes into
 * out and updates *outlen to the count produced; returns 0 on success, -1 on
 * a bad digit or if the result would not fit. Leading '1's become 0x00 bytes,
 * as in Bitcoin's base58. */
static int b58decode(const char *s, unsigned char *out, size_t *outlen)
{
    size_t slen = strlen(s), cap = *outlen;
    unsigned char *buf = calloc(slen ? slen : 1, 1);   /* base256, big-endian */
    if (!buf) return -1;
    size_t hi = slen;                                  /* index of top nonzero */

    for (size_t i = 0; i < slen; i++) {
        int d = b58val((unsigned char)s[i]);
        if (d < 0) { free(buf); return -1; }
        unsigned int carry = (unsigned int)d;
        size_t j = slen;
        while (j-- > hi || carry) {
            carry += 58u * buf[j];
            buf[j] = (unsigned char)(carry & 0xff);
            carry >>= 8;
            if (j == 0) break;
        }
        /* extend hi leftward to wherever the carry reached */
        while (hi > 0 && buf[hi - 1]) hi--;
    }

    /* leading '1' characters are leading zero bytes */
    size_t zeros = 0;
    while (zeros < slen && s[zeros] == '1') zeros++;

    size_t nbytes = (slen - hi) + zeros;
    if (nbytes > cap) { free(buf); return -1; }

    size_t k = 0;
    for (size_t i = 0; i < zeros; i++) out[k++] = 0;
    for (size_t i = hi; i < slen; i++) out[k++] = buf[i];
    *outlen = k;
    free(buf);
    return 0;
}

/* base58check-decode: decode, then verify the trailing 4-byte double-SHA256
 * checksum and strip it. On success writes the payload to out and sets
 * *outlen; returns 0, or -1 on a bad digit / short input / checksum mismatch. */
static int b58check_decode(const char *s, unsigned char *out, size_t *outlen)
{
    unsigned char raw[256];
    size_t n = sizeof raw;
    if (b58decode(s, raw, &n) != 0) return -1;
    if (n < 4) return -1;
    unsigned char sum[32];
    sha256d(raw, n - 4, sum);
    if (memcmp(sum, raw + n - 4, 4) != 0) return -1;   /* checksum */
    if (n - 4 > *outlen) return -1;
    memcpy(out, raw, n - 4);
    *outlen = n - 4;
    return 0;
}

/* ---- BIP38 (no-EC-multiply) parse -------------------------------------- */

struct bip38 {
    int           compressed;   /* flag & 0x20 */
    unsigned char addrhash[4];  /* the scrypt salt AND the only verifier */
    unsigned char enc1[16];
    unsigned char enc2[16];
};

/* Parse a 6P... key string. Returns 0 on success; -1 on a malformed key or a
 * key that is not no-EC-multiply (prefix != 0x0142). */
static int bip38_parse(const char *key, struct bip38 *b)
{
    unsigned char raw[64];
    size_t n = sizeof raw;
    if (b58check_decode(key, raw, &n) != 0) {
        fprintf(stderr, "rxe38: base58check decode failed (bad key or checksum)\n");
        return -1;
    }
    if (n != 39) {
        fprintf(stderr, "rxe38: unexpected payload length %zu (want 39)\n", n);
        return -1;
    }
    if (raw[0] != 0x01 || raw[1] != 0x42) {
        fprintf(stderr, "rxe38: not a no-EC-multiply BIP38 key "
                        "(prefix %02x%02x, want 0142)\n", raw[0], raw[1]);
        return -1;
    }
    b->compressed = (raw[2] & 0x20) != 0;
    memcpy(b->addrhash, raw + 3, 4);
    memcpy(b->enc1,     raw + 7, 16);
    memcpy(b->enc2,     raw + 23, 16);
    return 0;
}

/* ---- CLI (milestone 1: parse-and-dump) --------------------------------- */

static void hex(const char *label, const unsigned char *p, size_t n)
{
    printf("%s", label);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <6P...bip38key>\n", argv[0]);
        return 2;
    }
    struct bip38 b;
    if (bip38_parse(argv[1], &b) != 0) return 1;

    printf("prefix:     0142 (no-EC-multiply)\n");
    printf("compressed: %s\n", b.compressed ? "yes" : "no");
    hex("addrhash:   ", b.addrhash, 4);
    hex("enc1:       ", b.enc1, 16);
    hex("enc2:       ", b.enc2, 16);
    return 0;
}
