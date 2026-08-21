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

/* A parsed no-EC-multiply BIP38 key. */
struct bip38 {
    int           compressed;   /* flag & 0x20 */
    unsigned char addrhash[4];  /* the scrypt salt AND the only verifier */
    unsigned char enc1[16];
    unsigned char enc2[16];
};

/* ---- AES-256 (decrypt only, ECB, one block) ---------------------------- */

static const unsigned char AES_SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

static const unsigned char AES_RSBOX[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d };

/* GF(2^8) multiply, x^8 + x^4 + x^3 + x + 1. */
static unsigned char gmul(unsigned char a, unsigned char b)
{
    unsigned char r = 0;
    while (b) {
        if (b & 1) r ^= a;
        unsigned char hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return r;
}

/* Expand a 32-byte key into 15 round keys (240 bytes), column-major to match
 * the state (byte 4*c+r of round rnd = word w[4*rnd+c] byte r). */
static void aes256_key_expand(const unsigned char key[32], unsigned char rk[240])
{
    static const unsigned char RCON[8] = {0,0x01,0x02,0x04,0x08,0x10,0x20,0x40};
    unsigned char w[60][4];
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 4; j++) w[i][j] = key[4 * i + j];
    for (int i = 8; i < 60; i++) {
        unsigned char t[4] = { w[i-1][0], w[i-1][1], w[i-1][2], w[i-1][3] };
        if (i % 8 == 0) {
            unsigned char r = t[0];                     /* RotWord + SubWord */
            t[0] = AES_SBOX[t[1]] ^ RCON[i/8];
            t[1] = AES_SBOX[t[2]];
            t[2] = AES_SBOX[t[3]];
            t[3] = AES_SBOX[r];
        } else if (i % 8 == 4) {
            for (int j = 0; j < 4; j++) t[j] = AES_SBOX[t[j]];
        }
        for (int j = 0; j < 4; j++) w[i][j] = w[i-8][j] ^ t[j];
    }
    for (int i = 0; i < 60; i++)
        for (int j = 0; j < 4; j++) rk[4 * i + j] = w[i][j];
}

/* Decrypt one 16-byte block in place (FIPS-197 straightforward inverse
 * cipher, Nr=14). State is column-major: s[4*c + r]. */
static void aes256_decrypt_block(const unsigned char rk[240], unsigned char s[16])
{
    for (int i = 0; i < 16; i++) s[i] ^= rk[14 * 16 + i];   /* AddRoundKey(14) */
    for (int round = 13; round >= 1; round--) {
        /* InvShiftRows: row r rotated right by r */
        unsigned char t[16];
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                t[4 * c + r] = s[4 * ((c + 4 - r) & 3) + r];
        /* InvSubBytes */
        for (int i = 0; i < 16; i++) s[i] = AES_RSBOX[t[i]];
        /* AddRoundKey */
        for (int i = 0; i < 16; i++) s[i] ^= rk[round * 16 + i];
        /* InvMixColumns */
        for (int c = 0; c < 4; c++) {
            unsigned char *col = s + 4 * c;
            unsigned char a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
            col[0] = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3, 9);
            col[1] = gmul(a0, 9) ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13);
            col[2] = gmul(a0,13) ^ gmul(a1, 9) ^ gmul(a2,14) ^ gmul(a3,11);
            col[3] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2, 9) ^ gmul(a3,14);
        }
    }
    unsigned char t[16];                                   /* final round */
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            t[4 * c + r] = s[4 * ((c + 4 - r) & 3) + r];
    for (int i = 0; i < 16; i++) s[i] = AES_RSBOX[t[i]] ^ rk[i];
}

/* ---- BIP38 candidate: scrypt + AES + XOR -> private key ---------------- */

/* Given a parsed key and a passphrase, recover the candidate 32-byte private
 * key. Does NOT yet verify the address (milestone 4). */
static void bip38_privkey(const struct bip38 *b,
                          const unsigned char *pw, size_t pwlen,
                          unsigned char priv[32])
{
    unsigned char d[64];
    scrypt_kdf(pw, pwlen, b->addrhash, 4, 16384, 8, 8, d, 64);
    const unsigned char *dh1 = d, *dh2 = d + 32;
    unsigned char rk[240];
    aes256_key_expand(dh2, rk);

    unsigned char blk[16];
    memcpy(blk, b->enc1, 16);
    aes256_decrypt_block(rk, blk);
    for (int i = 0; i < 16; i++) priv[i] = blk[i] ^ dh1[i];
    memcpy(blk, b->enc2, 16);
    aes256_decrypt_block(rk, blk);
    for (int i = 0; i < 16; i++) priv[16 + i] = blk[i] ^ dh1[16 + i];
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

/* Decode a hex string into bytes (exactly n bytes expected). */
static void unhex(const char *h, unsigned char *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        int hi = h[2*i], lo = h[2*i+1];
        hi = (hi <= '9') ? hi - '0' : (hi | 32) - 'a' + 10;
        lo = (lo <= '9') ? lo - '0' : (lo | 32) - 'a' + 10;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
}

/* Milestone-3 self-test: FIPS-197 AES-256 decrypt + oracle private keys. */
static int test_priv(void)
{
    int ok = 1;

    /* FIPS-197 Appendix C.3 AES-256 vector: decrypt(ct) == pt. */
    unsigned char key[32], ct[16];
    unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, 32);
    unhex("8ea2b7ca516745bfeafc49904b496089", ct, 16);
    unsigned char rk[240];
    aes256_key_expand(key, rk);
    aes256_decrypt_block(rk, ct);
    ok &= check_hex("aes-fips", ct, 16, "00112233445566778899aabbccddeeff");

    struct { const char *pw, *key, *priv; } V[] = {
      {"TestingOneTwoThree","6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
       "cbf4b9f70470856bb4f40f80b87edb90865997ffee6df315ab166d713af433a5"},
      {"Satoshi","6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
       "09c2686880095b1a4c249ee3ac4eea8a014f11e6f986d0b5025ac1f39afbd9ae"},
      {"TestingOneTwoThree","6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
       "cbf4b9f70470856bb4f40f80b87edb90865997ffee6df315ab166d713af433a5"},
      {"Satoshi","6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
       "09c2686880095b1a4c249ee3ac4eea8a014f11e6f986d0b5025ac1f39afbd9ae"},
    };
    for (int i = 0; i < 4; i++) {
        struct bip38 b;
        if (bip38_parse(V[i].key, &b) != 0) { ok = 0; continue; }
        unsigned char priv[32];
        bip38_privkey(&b, (const unsigned char *)V[i].pw, strlen(V[i].pw), priv);
        char name[16]; sprintf(name, "priv-v%d", i + 1);
        ok &= check_hex(name, priv, 32, V[i].priv);
    }
    printf("%s\n", ok ? "privkey: ALL PASS" : "privkey: FAILED");
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--test-scrypt") == 0)
        return test_scrypt();
    if (argc >= 2 && strcmp(argv[1], "--test-priv") == 0)
        return test_priv();

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
