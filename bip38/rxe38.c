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

/* ---- HMAC-SHA256 / PBKDF2 ---------------------------------------------- */

/* HMAC-SHA256(key, msg) -> out[32]. RFC 2104. Keys longer than the 64-byte
 * block are pre-hashed. */
static void hmac_sha256(const unsigned char *key, size_t klen,
                        const unsigned char *msg, size_t mlen,
                        unsigned char out[32])
{
    unsigned char k[64], ik[64], ok[64], ihash[32];
    memset(k, 0, sizeof k);
    if (klen > 64) rt_sha256(key, klen, k);            /* leaves the tail zero */
    else           memcpy(k, key, klen);
    for (int i = 0; i < 64; i++) { ik[i] = k[i] ^ 0x36; ok[i] = k[i] ^ 0x5c; }

    unsigned char *ibuf = malloc(64 + mlen);
    memcpy(ibuf, ik, 64);
    memcpy(ibuf + 64, msg, mlen);
    rt_sha256(ibuf, 64 + mlen, ihash);
    free(ibuf);

    unsigned char obuf[96];
    memcpy(obuf, ok, 64);
    memcpy(obuf + 64, ihash, 32);
    rt_sha256(obuf, 96, out);
}

/* PBKDF2-HMAC-SHA256 with iteration count fixed at 1 (all scrypt needs).
 * With c==1 each output block is just HMAC(P, S || INT32BE(i)). */
static void pbkdf2_hmac_sha256_c1(const unsigned char *p, size_t plen,
                                  const unsigned char *s, size_t slen,
                                  unsigned char *dk, size_t dklen)
{
    unsigned char *msg = malloc(slen + 4);
    memcpy(msg, s, slen);
    size_t blocks = (dklen + 31) / 32;
    for (size_t i = 1; i <= blocks; i++) {
        msg[slen + 0] = (unsigned char)(i >> 24);
        msg[slen + 1] = (unsigned char)(i >> 16);
        msg[slen + 2] = (unsigned char)(i >> 8);
        msg[slen + 3] = (unsigned char)(i);
        unsigned char t[32];
        hmac_sha256(p, plen, msg, slen + 4, t);
        size_t off = (i - 1) * 32, n = dklen - off < 32 ? dklen - off : 32;
        memcpy(dk + off, t, n);
    }
    free(msg);
}

/* ---- scrypt (RFC 7914) -------------------------------------------------- *
 * Little-endian host assumed (this whole tool targets x86 / SHA-NI): the
 * 64-byte scrypt blocks are handled as uint32 words loaded straight from the
 * byte buffers, which is an LE load. */

#define ROTL32(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

/* Salsa20/8 core, in place on 16 little-endian words. */
static void salsa20_8(uint32_t B[16])
{
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = B[i];
    for (int i = 0; i < 8; i += 2) {
        x[ 4] ^= ROTL32(x[ 0] + x[12],  7); x[ 8] ^= ROTL32(x[ 4] + x[ 0],  9);
        x[12] ^= ROTL32(x[ 8] + x[ 4], 13); x[ 0] ^= ROTL32(x[12] + x[ 8], 18);
        x[ 9] ^= ROTL32(x[ 5] + x[ 1],  7); x[13] ^= ROTL32(x[ 9] + x[ 5],  9);
        x[ 1] ^= ROTL32(x[13] + x[ 9], 13); x[ 5] ^= ROTL32(x[ 1] + x[13], 18);
        x[14] ^= ROTL32(x[10] + x[ 6],  7); x[ 2] ^= ROTL32(x[14] + x[10],  9);
        x[ 6] ^= ROTL32(x[ 2] + x[14], 13); x[10] ^= ROTL32(x[ 6] + x[ 2], 18);
        x[ 3] ^= ROTL32(x[15] + x[11],  7); x[ 7] ^= ROTL32(x[ 3] + x[15],  9);
        x[11] ^= ROTL32(x[ 7] + x[ 3], 13); x[15] ^= ROTL32(x[11] + x[ 7], 18);
        x[ 1] ^= ROTL32(x[ 0] + x[ 3],  7); x[ 2] ^= ROTL32(x[ 1] + x[ 0],  9);
        x[ 3] ^= ROTL32(x[ 2] + x[ 1], 13); x[ 0] ^= ROTL32(x[ 3] + x[ 2], 18);
        x[ 6] ^= ROTL32(x[ 5] + x[ 4],  7); x[ 7] ^= ROTL32(x[ 6] + x[ 5],  9);
        x[ 4] ^= ROTL32(x[ 7] + x[ 6], 13); x[ 5] ^= ROTL32(x[ 4] + x[ 7], 18);
        x[11] ^= ROTL32(x[10] + x[ 9],  7); x[ 8] ^= ROTL32(x[11] + x[10],  9);
        x[ 9] ^= ROTL32(x[ 8] + x[11], 13); x[10] ^= ROTL32(x[ 9] + x[ 8], 18);
        x[12] ^= ROTL32(x[15] + x[14],  7); x[13] ^= ROTL32(x[12] + x[15],  9);
        x[14] ^= ROTL32(x[13] + x[12], 13); x[15] ^= ROTL32(x[14] + x[13], 18);
    }
    for (int i = 0; i < 16; i++) B[i] += x[i];
}

/* scryptBlockMix on 2r 64-byte blocks (128*r bytes = 32*r words), in place.
 * Y is caller-provided scratch of the same size. */
static void blockmix(uint32_t *B, uint32_t *Y, int r)
{
    uint32_t X[16];
    memcpy(X, B + (2 * r - 1) * 16, 64);
    for (int i = 0; i < 2 * r; i++) {
        for (int k = 0; k < 16; k++) X[k] ^= B[i * 16 + k];
        salsa20_8(X);
        memcpy(Y + i * 16, X, 64);
    }
    /* regroup even blocks then odd blocks back into B */
    for (int i = 0; i < r; i++) memcpy(B + i * 16,       Y + (2 * i) * 16,     64);
    for (int i = 0; i < r; i++) memcpy(B + (r + i) * 16, Y + (2 * i + 1) * 16, 64);
}

/* scryptROMix on one 128*r-byte block, in place. V is scratch of N*128*r
 * bytes, Y is scratch of 128*r bytes. N must be a power of two. */
static void romix(uint32_t *B, int r, uint32_t N, uint32_t *V, uint32_t *Y)
{
    size_t words = 32 * (size_t)r;
    for (uint32_t i = 0; i < N; i++) {
        memcpy(V + i * words, B, words * 4);
        blockmix(B, Y, r);
    }
    for (uint32_t i = 0; i < N; i++) {
        uint32_t j = B[(2 * r - 1) * 16] & (N - 1);     /* Integerify mod N */
        for (size_t k = 0; k < words; k++) B[k] ^= V[j * words + k];
        blockmix(B, Y, r);
    }
}

/* scrypt(P, S, N, r, p, dkLen). Returns 0 on success, -1 on OOM. */
static int scrypt_kdf(const unsigned char *pw, size_t pwlen,
                      const unsigned char *salt, size_t saltlen,
                      uint32_t N, int r, int p,
                      unsigned char *dk, size_t dklen)
{
    size_t blocklen = 128 * (size_t)r;                  /* bytes per ROMix block */
    unsigned char *B = malloc(blocklen * p);
    uint32_t *V = malloc(blocklen * (size_t)N);
    uint32_t *Y = malloc(blocklen);
    if (!B || !V || !Y) { free(B); free(V); free(Y); return -1; }

    pbkdf2_hmac_sha256_c1(pw, pwlen, salt, saltlen, B, blocklen * p);
    for (int i = 0; i < p; i++)
        romix((uint32_t *)(B + (size_t)i * blocklen), r, N, V, Y);
    pbkdf2_hmac_sha256_c1(pw, pwlen, B, blocklen * p, dk, dklen);

    free(B); free(V); free(Y);
    return 0;
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

/* Compare a computed digest against an expected hex string; print PASS/FAIL. */
static int check_hex(const char *name, const unsigned char *got, size_t n,
                     const char *want)
{
    char h[256];
    for (size_t i = 0; i < n; i++) sprintf(h + i * 2, "%02x", got[i]);
    int ok = strcmp(h, want) == 0;
    printf("[%s] %-10s %s\n", ok ? "PASS" : "FAIL", name, h);
    if (!ok) printf("            want   %s\n", want);
    return ok;
}

/* Milestone-2 self-test: RFC 7914 scrypt vectors + the oracle's dh1||dh2. */
static int test_scrypt(void)
{
    unsigned char dk[64];
    int ok = 1;

    scrypt_kdf((const unsigned char *)"", 0, (const unsigned char *)"", 0,
               16, 1, 1, dk, 64);
    ok &= check_hex("rfc-v1", dk, 64,
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
        "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");

    scrypt_kdf((const unsigned char *)"password", 8,
               (const unsigned char *)"NaCl", 4, 1024, 8, 16, dk, 64);
    ok &= check_hex("rfc-v2", dk, 64,
        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
        "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");

    scrypt_kdf((const unsigned char *)"pleaseletmein", 13,
               (const unsigned char *)"SodiumChloride", 14, 16384, 8, 1, dk, 64);
    ok &= check_hex("rfc-v3", dk, 64,
        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
        "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887");

    /* BIP38 spec vector 1: pass=TestingOneTwoThree, salt=addrhash e957a24a,
     * the actual N=16384,r=8,p=8 workload rxe38 will run per candidate. */
    unsigned char salt[4] = { 0xe9, 0x57, 0xa2, 0x4a };
    scrypt_kdf((const unsigned char *)"TestingOneTwoThree", 18, salt, 4,
               16384, 8, 8, dk, 64);
    ok &= check_hex("bip38-v1", dk, 64,
        "f87648a6b42fdd86ef6837a249cde15318f264d43a859b610e78ea63d51cb2d3"
        "e60bf44bfb29d543bba24afcccfadbfc6ef9312fcccf589fa5ea1366ec21e4c0");

    printf("%s\n", ok ? "scrypt: ALL PASS" : "scrypt: FAILED");
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--test-scrypt") == 0)
        return test_scrypt();

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
