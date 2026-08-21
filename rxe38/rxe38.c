/*
 * rxe38 -- crack a BIP38-encrypted Bitcoin private key (no-EC-multiply mode)
 * by trying passphrases drawn from a regex-described keyspace.
 *
 * Built in milestones, each diffed against rxe38/oracle.py (the
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
#include <time.h>
#include <pthread.h>
#include <gmp.h>

#include "rxe.h"                 /* the librxe enumerator */

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
/* Finish a candidate from its 64-byte scrypt output d = dh1||dh2 (AES + XOR).
 * Split out so the GPU backend can feed device-computed scrypt straight in. */
static void bip38_finish(const struct bip38 *b, const unsigned char d[64],
                         unsigned char priv[32])
{
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

static void bip38_privkey(const struct bip38 *b,
                          const unsigned char *pw, size_t pwlen,
                          unsigned char priv[32])
{
    unsigned char d[64];
    scrypt_kdf(pw, pwlen, b->addrhash, 4, 16384, 8, 8, d, 64);
    bip38_finish(b, d, priv);
}

/* ---- RIPEMD-160 -------------------------------------------------------- */

static uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static uint32_t rmd_f(int g, uint32_t x, uint32_t y, uint32_t z)
{
    switch (g) {
        case 0:  return x ^ y ^ z;
        case 1:  return (x & y) | (~x & z);
        case 2:  return (x | ~y) ^ z;
        case 3:  return (x & z) | (y & ~z);
        default: return x ^ (y | ~z);
    }
}

static void ripemd160(const unsigned char *msg, size_t len, unsigned char out[20])
{
    static const unsigned char RL[80] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
        3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
        1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
        4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13 };
    static const unsigned char RR[80] = {
        5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
        6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
        15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
        8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
        12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11 };
    static const unsigned char SL[80] = {
        11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
        7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
        11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
        11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
        9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6 };
    static const unsigned char SR[80] = {
        8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
        9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
        9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
        15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
        8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11 };
    static const uint32_t KL[5] = {0,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E};
    static const uint32_t KR[5] = {0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0};

    uint32_t h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0;

    size_t total = ((len + 8) / 64 + 1) * 64;
    unsigned char *buf = calloc(total, 1);
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) buf[total - 8 + i] = (unsigned char)(bits >> (8 * i));

    for (size_t off = 0; off < total; off += 64) {
        uint32_t X[16];
        for (int i = 0; i < 16; i++)
            X[i] = buf[off+4*i] | (buf[off+4*i+1]<<8) |
                   (buf[off+4*i+2]<<16) | ((uint32_t)buf[off+4*i+3]<<24);
        uint32_t al=h0,bl=h1,cl=h2,dl=h3,el=h4;
        uint32_t ar=h0,br=h1,cr=h2,dr=h3,er=h4;
        for (int j = 0; j < 80; j++) {
            int g = j / 16, gg = 4 - g;
            uint32_t t = rol32(al + rmd_f(g,bl,cl,dl) + X[RL[j]] + KL[g], SL[j]) + el;
            al=el; el=dl; dl=rol32(cl,10); cl=bl; bl=t;
            t = rol32(ar + rmd_f(gg,br,cr,dr) + X[RR[j]] + KR[g], SR[j]) + er;
            ar=er; er=dr; dr=rol32(cr,10); cr=br; br=t;
        }
        uint32_t t = h1 + cl + dr;
        h1 = h2 + dl + er; h2 = h3 + el + ar;
        h3 = h4 + al + br; h4 = h0 + bl + cr; h0 = t;
    }
    free(buf);
    uint32_t h[5] = {h0,h1,h2,h3,h4};
    for (int i = 0; i < 5; i++)
        for (int k = 0; k < 4; k++) out[4*i+k] = (unsigned char)(h[i] >> (8*k));
}

/* hash160 = RIPEMD160(SHA256(data)), the Bitcoin pubkey/script hash. */
static void hash160(const unsigned char *data, size_t len, unsigned char out[20])
{
    unsigned char sh[32];
    rt_sha256(data, len, sh);
    ripemd160(sh, 32, out);
}

/* ---- secp256k1 scalar multiply (affine, on gmp) ------------------------ *
 * We need exactly one thing: privkey*G -> pubkey. Affine double-and-add with
 * a modular inverse per step is plenty here -- one multiply per candidate is
 * dwarfed by scrypt. */

static mpz_t SP, SGX, SGY;      /* field prime, generator x/y */
static int secp_inited = 0;

static void secp_init(void)
{
    if (secp_inited) return;
    mpz_init_set_str(SP,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    mpz_init_set_str(SGX,
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    mpz_init_set_str(SGY,
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    secp_inited = 1;
}

struct pt { mpz_t x, y; int inf; };

static void pt_init(struct pt *p) { mpz_init(p->x); mpz_init(p->y); p->inf = 1; }
static void pt_clear(struct pt *p) { mpz_clear(p->x); mpz_clear(p->y); }
static void pt_set(struct pt *d, const struct pt *s)
{ mpz_set(d->x, s->x); mpz_set(d->y, s->y); d->inf = s->inf; }

/* R = 2P (R may alias P). */
static void pt_double(struct pt *R, const struct pt *P)
{
    if (P->inf || mpz_sgn(P->y) == 0) { R->inf = 1; return; }
    mpz_t lam, t, x3, y3;
    mpz_inits(lam, t, x3, y3, NULL);
    mpz_mul(lam, P->x, P->x); mpz_mul_ui(lam, lam, 3);      /* 3x^2 */
    mpz_mul_ui(t, P->y, 2); mpz_invert(t, t, SP);           /* 1/(2y) */
    mpz_mul(lam, lam, t); mpz_mod(lam, lam, SP);
    mpz_mul(x3, lam, lam); mpz_submul_ui(x3, P->x, 2); mpz_mod(x3, x3, SP);
    mpz_sub(y3, P->x, x3); mpz_mul(y3, y3, lam); mpz_sub(y3, y3, P->y);
    mpz_mod(y3, y3, SP);
    mpz_set(R->x, x3); mpz_set(R->y, y3); R->inf = 0;
    mpz_clears(lam, t, x3, y3, NULL);
}

/* R = P + Q (R may alias neither for simplicity; callers pass distinct). */
static void pt_add(struct pt *R, const struct pt *P, const struct pt *Q)
{
    if (P->inf) { pt_set(R, Q); return; }
    if (Q->inf) { pt_set(R, P); return; }
    if (mpz_cmp(P->x, Q->x) == 0) {
        if (mpz_cmp(P->y, Q->y) == 0) { pt_double(R, P); return; }
        R->inf = 1; return;                                 /* P + (-P) */
    }
    mpz_t lam, t, x3, y3;
    mpz_inits(lam, t, x3, y3, NULL);
    mpz_sub(lam, Q->y, P->y);
    mpz_sub(t, Q->x, P->x); mpz_invert(t, t, SP);
    mpz_mul(lam, lam, t); mpz_mod(lam, lam, SP);
    mpz_mul(x3, lam, lam); mpz_sub(x3, x3, P->x); mpz_sub(x3, x3, Q->x);
    mpz_mod(x3, x3, SP);
    mpz_sub(y3, P->x, x3); mpz_mul(y3, y3, lam); mpz_sub(y3, y3, P->y);
    mpz_mod(y3, y3, SP);
    mpz_set(R->x, x3); mpz_set(R->y, y3); R->inf = 0;
    mpz_clears(lam, t, x3, y3, NULL);
}

/* Derive the (compressed or uncompressed) SEC pubkey from a 32-byte privkey.
 * Writes 33 or 65 bytes to out and sets *outlen. */
static void priv_to_pubkey(const unsigned char priv[32], int compressed,
                           unsigned char *out, size_t *outlen)
{
    secp_init();
    mpz_t k; mpz_init(k);
    mpz_import(k, 32, 1, 1, 1, 0, priv);                    /* big-endian */

    struct pt R, G, T;
    pt_init(&R); pt_init(&G); pt_init(&T);
    mpz_set(G.x, SGX); mpz_set(G.y, SGY); G.inf = 0;

    for (int bit = 255; bit >= 0; bit--) {
        struct pt D; pt_init(&D);
        pt_double(&D, &R); pt_set(&R, &D); pt_clear(&D);
        if (mpz_tstbit(k, bit)) { pt_add(&T, &R, &G); pt_set(&R, &T); }
    }

    unsigned char xb[32];
    size_t cnt = 0;
    memset(xb, 0, 32);
    mpz_export(xb + (32 - (mpz_sizeinbase(R.x, 2) + 7) / 8), &cnt, 1, 1, 1, 0, R.x);
    if (compressed) {
        out[0] = mpz_tstbit(R.y, 0) ? 0x03 : 0x02;
        memcpy(out + 1, xb, 32);
        *outlen = 33;
    } else {
        unsigned char yb[32]; memset(yb, 0, 32);
        mpz_export(yb + (32 - (mpz_sizeinbase(R.y, 2) + 7) / 8), &cnt, 1, 1, 1, 0, R.y);
        out[0] = 0x04;
        memcpy(out + 1, xb, 32);
        memcpy(out + 33, yb, 32);
        *outlen = 65;
    }
    mpz_clear(k);
    pt_clear(&R); pt_clear(&G); pt_clear(&T);
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

/* base58-encode raw bytes into out (NUL-terminated). out must hold at least
 * len*138/100 + 2 chars. Leading zero bytes become leading '1's. */
static void b58encode(const unsigned char *data, size_t len, char *out)
{
    size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) zeros++;
    size_t size = (len - zeros) * 138 / 100 + 1;
    unsigned char *b = calloc(size, 1);
    for (size_t i = zeros; i < len; i++) {
        unsigned int carry = data[i];
        for (size_t k = size; k-- > 0; ) {
            carry += 256u * b[k];
            b[k] = (unsigned char)(carry % 58);
            carry /= 58;
        }
    }
    size_t j = 0;
    while (j < size && b[j] == 0) j++;
    size_t o = 0;
    for (size_t i = 0; i < zeros; i++) out[o++] = '1';
    for (; j < size; j++) out[o++] = B58[b[j]];
    out[o] = '\0';
    free(b);
}

/* base58check-encode: append the 4-byte double-SHA256 checksum, then encode. */
static void b58check_encode(const unsigned char *data, size_t len, char *out)
{
    unsigned char *buf = malloc(len + 4);
    memcpy(buf, data, len);
    unsigned char sum[32];
    sha256d(data, len, sum);
    memcpy(buf + len, sum, 4);
    b58encode(buf, len + 4, out);
    free(buf);
}

/* ---- address + full BIP38 verify --------------------------------------- */

/* Compute the P2PKH base58 address (mainnet, version 0x00) for a private key.
 * Writes a NUL-terminated string (<=35 chars) to addr. */
static void privkey_to_address(const unsigned char priv[32], int compressed,
                               char *addr)
{
    unsigned char pub[65];
    size_t publen;
    priv_to_pubkey(priv, compressed, pub, &publen);
    unsigned char payload[21];
    payload[0] = 0x00;
    hash160(pub, publen, payload + 1);
    b58check_encode(payload, 21, addr);
}

/* The only verifier in a no-EC-multiply key: the address's own double-SHA256
 * hash, first 4 bytes, must equal addrhash. Returns 1 on a match. */
static int address_matches(const unsigned char priv[32], int compressed,
                           const unsigned char addrhash[4])
{
    char addr[40];
    privkey_to_address(priv, compressed, addr);
    unsigned char sum[32];
    sha256d((const unsigned char *)addr, strlen(addr), sum);
    return memcmp(sum, addrhash, 4) == 0;
}

/* WIF-encode a private key, for reporting a crack. */
static void privkey_to_wif(const unsigned char priv[32], int compressed, char *wif)
{
    unsigned char payload[34];
    payload[0] = 0x80;
    memcpy(payload + 1, priv, 32);
    size_t len = 33;
    if (compressed) payload[33] = 0x01, len = 34;
    b58check_encode(payload, len, wif);
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

/* Milestone-4 self-test: the correctness GATE. RIPEMD-160 units, then full
 * pubkey/address derivation and addrhash verify for all four spec vectors,
 * plus a wrong-passphrase negative check. */
static int test_verify(void)
{
    int ok = 1;
    unsigned char h[20];
    ripemd160((const unsigned char *)"", 0, h);
    ok &= check_hex("rmd-empty", h, 20, "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    ripemd160((const unsigned char *)"abc", 3, h);
    ok &= check_hex("rmd-abc", h, 20, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");

    struct { const char *pw, *key, *pub, *addr; } V[] = {
      {"TestingOneTwoThree","6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
       "04d2ce831dd06e5c1f5b1121ef34c2af4bcb01b126e309234adbc3561b60c9360e"
       "a7f23327b49ba7f10d17fad15f068b8807dbbc9e4ace5d4a0b40264eefaf31a4",
       "1Jq6MksXQVWzrznvZzxkV6oY57oWXD9TXB"},
      {"Satoshi","6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
       "0463b600a0bb6a2f2bef7bb9648222c3593a6ef5f7c2d81433c5193bf84b9f862b"
       "940e55da162aeca6293cde138bcc18ba978fae399f14f258afa4f799ee61adcb",
       "1AvKt49sui9zfzGeo8EyL8ypvAhtR2KwbL"},
      {"TestingOneTwoThree","6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
       "02d2ce831dd06e5c1f5b1121ef34c2af4bcb01b126e309234adbc3561b60c9360e",
       "164MQi977u9GUteHr4EPH27VkkdxmfCvGW"},
      {"Satoshi","6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
       "0363b600a0bb6a2f2bef7bb9648222c3593a6ef5f7c2d81433c5193bf84b9f862b",
       "1HmPbwsvG5qJ3KJfxzsZRZWhbm1xBMuS8B"},
    };
    for (int i = 0; i < 4; i++) {
        struct bip38 b;
        if (bip38_parse(V[i].key, &b) != 0) { ok = 0; continue; }
        unsigned char priv[32];
        bip38_privkey(&b, (const unsigned char *)V[i].pw, strlen(V[i].pw), priv);

        unsigned char pub[65]; size_t publen;
        priv_to_pubkey(priv, b.compressed, pub, &publen);
        char nm[16];
        sprintf(nm, "pub-v%d", i + 1);
        ok &= check_hex(nm, pub, publen, V[i].pub);

        char addr[40];
        privkey_to_address(priv, b.compressed, addr);
        int amatch = strcmp(addr, V[i].addr) == 0;
        int vmatch = address_matches(priv, b.compressed, b.addrhash);
        printf("[%s] addr-v%d   %s (verify=%d)\n",
               (amatch && vmatch) ? "PASS" : "FAIL", i + 1, addr, vmatch);
        ok &= amatch && vmatch;
    }

    /* Negative: a wrong passphrase must NOT verify against vector 1. */
    struct bip38 b;
    bip38_parse("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg", &b);
    unsigned char priv[32];
    bip38_privkey(&b, (const unsigned char *)"WrongPassphrase", 15, priv);
    int neg = address_matches(priv, b.compressed, b.addrhash);
    printf("[%s] negative   wrong passphrase verify=%d (want 0)\n",
           neg == 0 ? "PASS" : "FAIL", neg);
    ok &= (neg == 0);

    printf("%s\n", ok ? "verify: ALL PASS -- CORRECTNESS GATE GREEN" : "verify: FAILED");
    return ok ? 0 : 1;
}

/* ---- the cracker: librxe enumeration + pthreads ------------------------ */

/* Human-readable rate: H/s, KH/s, ... (candidates are "H" here). */
static const char *fmt_rate(double r, char *b)
{
    static const char *u[] = {"H/s","KH/s","MH/s","GH/s","TH/s"};
    int i = 0;
    while (r >= 1000.0 && i < 4) { r /= 1000.0; i++; }
    sprintf(b, "%.3g %s", r, u[i]);
    return b;
}

/* Human-readable ETA, largest two units, from a seconds count. */
static const char *fmt_eta(double s, char *b)
{
    if (s < 0 || s > 1e18) { sprintf(b, "eons"); return b; }
    unsigned long long t = (unsigned long long)s;
    unsigned long long y = t/31557600ULL; t %= 31557600ULL;
    unsigned long long d = t/86400ULL;    t %= 86400ULL;
    unsigned long long h = t/3600ULL;     t %= 3600ULL;
    unsigned long long m = t/60ULL;       t %= 60ULL;
    if (y)      sprintf(b, "%lluy %llud", y, d);
    else if (d) sprintf(b, "%llud %lluh", d, h);
    else if (h) sprintf(b, "%lluh %llum", h, m);
    else if (m) sprintf(b, "%llum %llus", m, t);
    else        sprintf(b, "%llus", t);
    return b;
}

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Shared across all shards: the parsed key, the stop flag, the winning hit. */
struct crack {
    const struct bip38 *key;
    volatile int        stop;        /* set once a shard verifies a hit */
    pthread_mutex_t     mtx;
    char                pass[512];    /* the found passphrase */
    char                wif[64];      /* its WIF */
    mpz_t               hit_index;
};

struct shard {
    struct rxe        *rxe;
    mpz_t              from, count;
    struct crack      *cr;
    volatile unsigned long tried;     /* candidates this shard has verified */
};

/* Per-candidate sink: BIP38-decrypt with this passphrase and verify. */
static int crack_sink(const char *str, size_t len, const mpz_t index, void *v)
{
    struct shard *s = v;
    if (s->cr->stop) return 1;                     /* another shard won */
    s->tried++;

    unsigned char priv[32];
    bip38_privkey(s->cr->key, (const unsigned char *)str, len, priv);
    if (address_matches(priv, s->cr->key->compressed, s->cr->key->addrhash)) {
        pthread_mutex_lock(&s->cr->mtx);
        if (!s->cr->stop) {
            size_t n = len < sizeof s->cr->pass - 1 ? len : sizeof s->cr->pass - 1;
            memcpy(s->cr->pass, str, n); s->cr->pass[n] = '\0';
            privkey_to_wif(priv, s->cr->key->compressed, s->cr->wif);
            mpz_set(s->cr->hit_index, index);
            s->cr->stop = 1;
        }
        pthread_mutex_unlock(&s->cr->mtx);
        return 1;
    }
    return 0;
}

static void *crack_worker(void *arg)
{
    struct shard *s = arg;
    rxe_foreach(s->rxe, s->from, s->count, 512, crack_sink, s);
    return NULL;
}

/* Progress monitor: prints an aggregate rate + ETA once a second on stderr. */
struct monitor {
    struct shard *sh;
    int           T;
    volatile int *done;
    double        t0;
    double        total;             /* candidate count, or <0 if unbounded */
};

static void *monitor_thread(void *arg)
{
    struct monitor *m = arg;
    while (!*m->done) {
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
        if (*m->done) break;
        unsigned long tried = 0;
        for (int i = 0; i < m->T; i++) tried += m->sh[i].tried;
        double dt = now_sec() - m->t0;
        double rate = dt > 0 ? tried / dt : 0;
        char rb[32], eb[32];
        if (m->total >= 0) {
            double rem = m->total - tried;
            double eta = rate > 0 ? rem / rate : -1;
            double pct = m->total > 0 ? 100.0 * tried / m->total : 0;
            fprintf(stderr, "\rrxe38: %lu tried, %s, %.2f%%, eta %s      ",
                    tried, fmt_rate(rate, rb), pct, fmt_eta(eta, eb));
        } else {
            fprintf(stderr, "\rrxe38: %lu tried, %s      ",
                    tried, fmt_rate(rate, rb));
        }
    }
    return NULL;
}

#define RXE38_THREAD_MIN 4          /* below this many candidates, one thread */

/* Drive the crack. Returns 0 on a hit (prints it), 1 on exhaustion. */
static int crack(const struct bip38 *key, const char *pattern,
                 int jobs, int progress, long cap)
{
    struct rxe *rxe = rxe_parse(pattern, 0);
    if (!rxe || rxe_error(rxe)) {
        fprintf(stderr, "rxe38: bad passphrase regex: %s\n",
                rxe ? rxe_error_message(rxe) : "parse failed");
        if (rxe) rxe_free(rxe);
        return 2;
    }
    int infinite = rxe_is_infinite(rxe);

    /* How many candidates the walk covers, as a concrete count to divide. */
    mpz_t nwalk; mpz_init(nwalk);
    int bounded = 1;
    if (infinite) {
        if (cap > 0) mpz_set_si(nwalk, cap);
        else { bounded = 0; mpz_set_ui(nwalk, 0); }
    } else if (cap > 0 && mpz_cmp_si(rxe->nitems, cap) > 0) {
        mpz_set_si(nwalk, cap);
    } else {
        mpz_set(nwalk, rxe->nitems);
    }

    int T = jobs > 0 ? jobs : 1;
    if (!bounded) { /* unbounded infinite walk: single shard, no division */
        T = 1;
    } else if (mpz_cmp_ui(nwalk, RXE38_THREAD_MIN) < 0) {
        T = 1;
        if (mpz_sgn(nwalk) > 0 && mpz_cmp_ui(nwalk, (unsigned)T) < 0)
            T = (int)mpz_get_ui(nwalk);
    }
    if (T < 1) T = 1;

    struct crack cr;
    cr.key = key; cr.stop = 0; cr.pass[0] = 0; cr.wif[0] = 0;
    pthread_mutex_init(&cr.mtx, NULL);
    mpz_init(cr.hit_index);

    struct shard *sh = calloc((size_t)T, sizeof *sh);
    if (T == 1) {
        mpz_init_set_ui(sh[0].from, 0);
        mpz_init(sh[0].count);
        if (bounded) mpz_set(sh[0].count, nwalk);       /* else 0 = unlimited */
        sh[0].rxe = rxe; sh[0].cr = &cr;
    } else {
        mpz_t base, off, r;
        mpz_inits(base, off, r, NULL);
        mpz_tdiv_qr_ui(base, r, nwalk, (unsigned long)T);
        unsigned long rem = mpz_get_ui(r);
        for (int t = 0; t < T; t++) {
            mpz_init_set(sh[t].from, off);
            mpz_init_set(sh[t].count, base);
            if ((unsigned long)t < rem) mpz_add_ui(sh[t].count, sh[t].count, 1);
            mpz_add(off, off, sh[t].count);
            sh[t].rxe = (t == 0) ? rxe : rxe_deep_clone(rxe);
            sh[t].cr  = &cr;
        }
        mpz_clears(base, off, r, NULL);
    }

    double t0 = now_sec();
    volatile int mdone = 0;
    struct monitor mon = { sh, T, &mdone, t0, bounded ? mpz_get_d(nwalk) : -1.0 };
    pthread_t montid; int mon_on = 0;
    if (progress)
        mon_on = pthread_create(&montid, NULL, monitor_thread, &mon) == 0;

    pthread_t *tid = calloc((size_t)T, sizeof *tid);
    char *spun = calloc((size_t)T, 1);
    for (int t = 1; t < T; t++)
        if (pthread_create(&tid[t], NULL, crack_worker, &sh[t]) == 0) spun[t] = 1;
        else crack_worker(&sh[t]);
    crack_worker(&sh[0]);
    for (int t = 1; t < T; t++) if (spun[t]) pthread_join(tid[t], NULL);
    mdone = 1;
    if (mon_on) pthread_join(montid, NULL);
    free(tid); free(spun);

    unsigned long tried = 0;
    for (int t = 0; t < T; t++) tried += sh[t].tried;
    double dt = now_sec() - t0;
    if (progress) fprintf(stderr, "\n");

    int rc;
    if (cr.stop) {
        printf("FOUND passphrase: %s\n", cr.pass);
        printf("WIF: %s\n", cr.wif);
        gmp_printf("index: %Zd   (%lu tried, %.1fs, %.1f cand/s)\n",
                   cr.hit_index, tried, dt, dt > 0 ? tried / dt : 0);
        rc = 0;
    } else {
        fprintf(stderr, "rxe38: not found (%lu tried, %.1fs, %.1f cand/s)\n",
                tried, dt, dt > 0 ? tried / dt : 0);
        rc = 1;
    }

    for (int t = 0; t < T; t++) {
        mpz_clear(sh[t].from); mpz_clear(sh[t].count);
        if (t != 0) rxe_free(sh[t].rxe);
    }
    rxe_free(rxe);
    free(sh);
    mpz_clear(nwalk); mpz_clear(cr.hit_index);
    pthread_mutex_destroy(&cr.mtx);
    return rc;
}

/* ---- GPU backend (OpenCL): scrypt on the device, verify on the host ----- *
 * Compiled only into the -gpu build (RXE38_GPU). scrypt is ~99.99% of the
 * per-candidate cost, so the kernel does just that; the host finishes AES +
 * secp256k1 + address-verify with the code above. */
#ifdef RXE38_GPU
#define CL_TARGET_OPENCL_VERSION 120  /* pin to 1.2: portable, clCreateCommandQueue */
#include <CL/cl.h>
#include "scrypt_cl_embed.h"          /* SCRYPT_CL: the kernel source string */

#define GPU_N     16384                 /* BIP38 scrypt parameters */
#define GPU_R     8
#define GPU_P     8
#define GPU_MAXPW 64                  /* GPU passphrases up to this many bytes */
#define GPU_BLK   (128 * GPU_R)       /* 1024 */

struct gpu {
    cl_device_id     dev;
    cl_context       ctx;
    cl_command_queue q;
    cl_kernel        k;               /* scrypt_kdf, monolithic (the test) */
    cl_kernel        kph;             /* scrypt_phase, chunked (the cracker) */
    cl_mem           mpw, mlen, mout, mV, mB, mY;
    size_t           cap;             /* lanes the buffers are sized for */
    char             devname[128];
};

#define CKG(e) do { cl_int _e = (e); if (_e != CL_SUCCESS) { \
    fprintf(stderr, "rxe38 gpu: OpenCL error %d at %s:%d\n", _e, __FILE__, __LINE__); \
    return -1; } } while (0)

/* Build the program and allocate the per-lane buffers for `cap` lanes. The V
 * scratchpad is 16 MB/lane, so `cap` is bounded by device memory. */
static int gpu_setup(struct gpu *g, size_t cap)
{
    cl_platform_id plat;
    cl_int e;
    CKG(clGetPlatformIDs(1, &plat, NULL));
    if (clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 1, &g->dev, NULL) != CL_SUCCESS) {
        fprintf(stderr, "rxe38 gpu: no OpenCL GPU device\n");
        return -1;
    }
    clGetDeviceInfo(g->dev, CL_DEVICE_NAME, sizeof g->devname, g->devname, NULL);
    g->ctx = clCreateContext(NULL, 1, &g->dev, NULL, NULL, &e); CKG(e);
    g->q   = clCreateCommandQueue(g->ctx, g->dev, 0, &e); CKG(e);

    const char *src = SCRYPT_CL;
    cl_program pr = clCreateProgramWithSource(g->ctx, 1, &src, NULL, &e); CKG(e);
    char opts[128];
    const char *dbg = getenv("RXE38_GPU_DBG");
    snprintf(opts, sizeof opts, "-D SN=%d -D SR=%d -D SP=%d -D MAXPW=%d -D DBG=%d",
             GPU_N, GPU_R, GPU_P, GPU_MAXPW, dbg ? atoi(dbg) : 0);
    if (clBuildProgram(pr, 1, &g->dev, opts, NULL, NULL) != CL_SUCCESS) {
        size_t ln = 0;
        clGetProgramBuildInfo(pr, g->dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &ln);
        char *log = malloc(ln + 1);
        clGetProgramBuildInfo(pr, g->dev, CL_PROGRAM_BUILD_LOG, ln, log, NULL);
        log[ln] = 0;
        fprintf(stderr, "rxe38 gpu: build failed:\n%s\n", log);
        free(log);
        return -1;
    }
    g->k   = clCreateKernel(pr, "scrypt_kdf", &e); CKG(e);
    g->kph = clCreateKernel(pr, "scrypt_phase", &e); CKG(e);
    clReleaseProgram(pr);

    g->cap = cap;
    g->mpw  = clCreateBuffer(g->ctx, CL_MEM_READ_ONLY,  cap * GPU_MAXPW, NULL, &e); CKG(e);
    g->mlen = clCreateBuffer(g->ctx, CL_MEM_READ_ONLY,  cap * sizeof(cl_uint), NULL, &e); CKG(e);
    g->mout = clCreateBuffer(g->ctx, CL_MEM_WRITE_ONLY, cap * 64, NULL, &e); CKG(e);
    g->mV   = clCreateBuffer(g->ctx, CL_MEM_READ_WRITE, cap * (size_t)GPU_BLK * GPU_N, NULL, &e); CKG(e);
    g->mB   = clCreateBuffer(g->ctx, CL_MEM_READ_WRITE, cap * (size_t)GPU_BLK * GPU_P, NULL, &e); CKG(e);
    g->mY   = clCreateBuffer(g->ctx, CL_MEM_READ_WRITE, cap * (size_t)GPU_BLK, NULL, &e); CKG(e);
    return 0;
}

/* Run one batch of `n` (<= cap) passphrases with a shared salt, returning the
 * 64-byte dh1||dh2 for each into out. */
static int gpu_run(struct gpu *g, const unsigned char *pw, const cl_uint *pwlen,
                   size_t n, const unsigned char salt[4], cl_uint N, unsigned char *out)
{
    CKG(clEnqueueWriteBuffer(g->q, g->mpw, CL_FALSE, 0, n * GPU_MAXPW, pw, 0, NULL, NULL));
    CKG(clEnqueueWriteBuffer(g->q, g->mlen, CL_FALSE, 0, n * sizeof(cl_uint), pwlen, 0, NULL, NULL));
    cl_uint saltw = salt[0] | ((cl_uint)salt[1]<<8) | ((cl_uint)salt[2]<<16) | ((cl_uint)salt[3]<<24);
    CKG(clSetKernelArg(g->k, 0, sizeof(cl_mem), &g->mpw));
    CKG(clSetKernelArg(g->k, 1, sizeof(cl_mem), &g->mlen));
    CKG(clSetKernelArg(g->k, 2, sizeof(cl_uint), &saltw));
    CKG(clSetKernelArg(g->k, 3, sizeof(cl_mem), &g->mout));
    CKG(clSetKernelArg(g->k, 4, sizeof(cl_mem), &g->mV));
    CKG(clSetKernelArg(g->k, 5, sizeof(cl_mem), &g->mB));
    CKG(clSetKernelArg(g->k, 6, sizeof(cl_mem), &g->mY));
    CKG(clSetKernelArg(g->k, 7, sizeof(cl_uint), &N));
    size_t global = n;
    CKG(clEnqueueNDRangeKernel(g->q, g->k, 1, NULL, &global, NULL, 0, NULL, NULL));
    CKG(clEnqueueReadBuffer(g->q, g->mout, CL_TRUE, 0, n * 64, out, 0, NULL, NULL));
    return 0;
}

/* Run a batch through the phased kernel: PBKDF2-1, then per ROMix pass a run of
 * fill and mix chunks of `chunk` iterations each, then PBKDF2-2. Each launch
 * does a bounded slice so no single submit trips a GPU watchdog. */
static int gpu_run_phased(struct gpu *g, const unsigned char *pw, const cl_uint *pwlen,
                          size_t n, const unsigned char salt[4], cl_uint N,
                          cl_uint chunk, unsigned char *out)
{
    CKG(clEnqueueWriteBuffer(g->q, g->mpw, CL_FALSE, 0, n * GPU_MAXPW, pw, 0, NULL, NULL));
    CKG(clEnqueueWriteBuffer(g->q, g->mlen, CL_FALSE, 0, n * sizeof(cl_uint), pwlen, 0, NULL, NULL));
    cl_uint saltw = salt[0] | ((cl_uint)salt[1]<<8) | ((cl_uint)salt[2]<<16) | ((cl_uint)salt[3]<<24);
    cl_uint zero = 0;
    /* fixed args */
    CKG(clSetKernelArg(g->kph, 0, sizeof(cl_mem), &g->mpw));
    CKG(clSetKernelArg(g->kph, 1, sizeof(cl_mem), &g->mlen));
    CKG(clSetKernelArg(g->kph, 2, sizeof(cl_uint), &saltw));
    CKG(clSetKernelArg(g->kph, 3, sizeof(cl_mem), &g->mout));
    CKG(clSetKernelArg(g->kph, 4, sizeof(cl_mem), &g->mV));
    CKG(clSetKernelArg(g->kph, 5, sizeof(cl_mem), &g->mB));
    CKG(clSetKernelArg(g->kph, 6, sizeof(cl_mem), &g->mY));
    CKG(clSetKernelArg(g->kph, 8, sizeof(cl_uint), &N));
    size_t global = n;

    #define LAUNCH(PHASE, PASS, I0, I1) do { \
        cl_uint _ph=(PHASE),_ps=(PASS),_i0=(I0),_i1=(I1); \
        CKG(clSetKernelArg(g->kph, 7, sizeof(cl_uint), &_ph)); \
        CKG(clSetKernelArg(g->kph, 9, sizeof(cl_uint), &_ps)); \
        CKG(clSetKernelArg(g->kph,10, sizeof(cl_uint), &_i0)); \
        CKG(clSetKernelArg(g->kph,11, sizeof(cl_uint), &_i1)); \
        CKG(clEnqueueNDRangeKernel(g->q, g->kph, 1, NULL, &global, NULL, 0, NULL, NULL)); \
    } while (0)

    LAUNCH(0, 0, 0, 0);                              /* PBKDF2-1 -> gB */
    for (cl_uint pass = 0; pass < GPU_P; pass++) {
        for (cl_uint s = 0; s < N; s += chunk)
            LAUNCH(1, pass, s, s + chunk < N ? s + chunk : N);   /* fill */
        for (cl_uint s = 0; s < N; s += chunk)
            LAUNCH(2, pass, s, s + chunk < N ? s + chunk : N);   /* mix */
    }
    LAUNCH(3, 0, 0, 0);                              /* PBKDF2-2 -> out */
    (void)zero;
    #undef LAUNCH
    CKG(clEnqueueReadBuffer(g->q, g->mout, CL_TRUE, 0, n * 64, out, 0, NULL, NULL));
    return 0;
}

static void gpu_teardown(struct gpu *g)
{
    clReleaseMemObject(g->mpw); clReleaseMemObject(g->mlen);
    clReleaseMemObject(g->mout); clReleaseMemObject(g->mV);
    clReleaseMemObject(g->mB); clReleaseMemObject(g->mY);
    clReleaseKernel(g->k); clReleaseKernel(g->kph);
    clReleaseCommandQueue(g->q); clReleaseContext(g->ctx);
}

/* --gpu-scrypt-test: run spec-vector passphrases through the kernel in a batch
 * and diff each lane's dh1||dh2 against the CPU scrypt. */
static int gpu_scrypt_test(cl_uint tn)
{
    struct gpu g;
    if (gpu_setup(&g, 8) != 0) return 1;
    printf("rxe38 gpu: device = %s (test N=%u; tool uses N=%d)\n",
           g.devname, tn, GPU_N);
    if (tn == GPU_N)
        fprintf(stderr, "rxe38 gpu: note -- N=%d takes seconds/lane; a display GPU's "
                        "watchdog may reset it. Use a smaller N here, or a headless GPU.\n", GPU_N);

    /* All lanes share vector 1's salt (e957a24a); mix real + junk passphrases. */
    unsigned char salt[4] = { 0xe9, 0x57, 0xa2, 0x4a };
    const char *pws[] = { "TestingOneTwoThree", "Satoshi", "hunter2", "",
                          "correct horse", "TestingOneTwoThre", "z", "A longer one!!" };
    size_t n = 8;
    unsigned char pwbuf[8 * GPU_MAXPW];
    cl_uint lens[8];
    memset(pwbuf, 0, sizeof pwbuf);
    for (size_t i = 0; i < n; i++) {
        size_t l = strlen(pws[i]);
        lens[i] = (cl_uint)l;
        memcpy(pwbuf + i * GPU_MAXPW, pws[i], l);
    }
    unsigned char gout[8 * 64];
    if (gpu_run(&g, pwbuf, lens, n, salt, tn, gout) != 0) { gpu_teardown(&g); return 1; }

    const char *dbg = getenv("RXE38_GPU_DBG");
    int stage = dbg ? atoi(dbg) : 0;

    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        unsigned char cpu[64];
        if (stage == 1) {                 /* CPU PBKDF2-1 first 64 bytes */
            unsigned char B[GPU_BLK * GPU_P];
            pbkdf2_hmac_sha256_c1((const unsigned char *)pws[i], strlen(pws[i]),
                                  salt, 4, B, sizeof B);
            memcpy(cpu, B, 64);
        } else if (stage == 2) {          /* CPU: PBKDF2-1 then romix block 0 */
            unsigned char B[GPU_BLK * GPU_P];
            pbkdf2_hmac_sha256_c1((const unsigned char *)pws[i], strlen(pws[i]),
                                  salt, 4, B, sizeof B);
            uint32_t *V = malloc((size_t)GPU_BLK * tn);
            uint32_t *Y = malloc(GPU_BLK);
            romix((uint32_t *)B, GPU_R, tn, V, Y);
            free(V); free(Y);
            memcpy(cpu, B, 64);
        } else if (stage == 3) {          /* CPU: PBKDF2-1 then one blockmix */
            unsigned char B[GPU_BLK * GPU_P];
            pbkdf2_hmac_sha256_c1((const unsigned char *)pws[i], strlen(pws[i]),
                                  salt, 4, B, sizeof B);
            uint32_t Y[GPU_BLK / 4];
            blockmix((uint32_t *)B, Y, GPU_R);
            memcpy(cpu, B, 64);
        } else if (stage == 4) {          /* CPU: PBKDF2-1 then N blockmixes */
            unsigned char B[GPU_BLK * GPU_P];
            pbkdf2_hmac_sha256_c1((const unsigned char *)pws[i], strlen(pws[i]),
                                  salt, 4, B, sizeof B);
            uint32_t Y[GPU_BLK / 4];
            for (cl_uint it = 0; it < tn; it++) blockmix((uint32_t *)B, Y, GPU_R);
            memcpy(cpu, B, 64);
        } else {                          /* full scrypt (stage 0) */
            scrypt_kdf((const unsigned char *)pws[i], strlen(pws[i]), salt, 4,
                       tn, GPU_R, GPU_P, cpu, 64);
        }
        int match = memcmp(cpu, gout + i * 64, 64) == 0;
        ok &= match;
        printf("[%s] lane %zu %-20s gpu=%02x%02x%02x%02x%02x%02x%02x%02x cpu=%02x%02x%02x%02x%02x%02x%02x%02x\n",
               match ? "PASS" : "FAIL", i, pws[i],
               gout[i*64],gout[i*64+1],gout[i*64+2],gout[i*64+3],gout[i*64+4],gout[i*64+5],gout[i*64+6],gout[i*64+7],
               cpu[0],cpu[1],cpu[2],cpu[3],cpu[4],cpu[5],cpu[6],cpu[7]);
    }
    gpu_teardown(&g);
    printf("%s\n", ok ? "gpu scrypt: ALL PASS -- matches CPU byte-exact"
                      : "gpu scrypt: FAILED");
    return ok ? 0 : 1;
}

/* --gpu-phase-test [N [chunk]]: validate the CHUNKED phased kernel against the
 * CPU scrypt (default chunk = N/4 to exercise multi-chunk resumption). */
static int gpu_phase_test(cl_uint tn, cl_uint chunk)
{
    struct gpu g;
    if (gpu_setup(&g, 8) != 0) return 1;
    if (chunk == 0) chunk = tn >= 4 ? tn / 4 : tn;
    printf("rxe38 gpu: device = %s (phased test N=%u chunk=%u)\n", g.devname, tn, chunk);

    unsigned char salt[4] = { 0xe9, 0x57, 0xa2, 0x4a };
    const char *pws[] = { "TestingOneTwoThree", "Satoshi", "hunter2", "",
                          "correct horse", "TestingOneTwoThre", "z", "A longer one!!" };
    size_t n = 8;
    unsigned char pwbuf[8 * GPU_MAXPW];
    cl_uint lens[8];
    memset(pwbuf, 0, sizeof pwbuf);
    for (size_t i = 0; i < n; i++) {
        lens[i] = (cl_uint)strlen(pws[i]);
        memcpy(pwbuf + i * GPU_MAXPW, pws[i], lens[i]);
    }
    unsigned char gout[8 * 64];
    if (gpu_run_phased(&g, pwbuf, lens, n, salt, tn, chunk, gout) != 0) { gpu_teardown(&g); return 1; }

    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        unsigned char cpu[64];
        scrypt_kdf((const unsigned char *)pws[i], strlen(pws[i]), salt, 4,
                   tn, GPU_R, GPU_P, cpu, 64);
        int match = memcmp(cpu, gout + i * 64, 64) == 0;
        ok &= match;
        printf("[%s] lane %zu %-20s gpu=%02x%02x%02x%02x cpu=%02x%02x%02x%02x\n",
               match ? "PASS" : "FAIL", i, pws[i],
               gout[i*64],gout[i*64+1],gout[i*64+2],gout[i*64+3], cpu[0],cpu[1],cpu[2],cpu[3]);
    }
    gpu_teardown(&g);
    printf("%s\n", ok ? "gpu phased scrypt: ALL PASS" : "gpu phased scrypt: FAILED");
    return ok ? 0 : 1;
}

/* Batched GPU crack: enumerate the regex on the host, fill a batch of
 * passphrases, run scrypt on the device, finish + verify on the host. */
struct gpu_crack {
    struct gpu         *g;
    const struct bip38 *key;
    cl_uint             N;
    cl_uint             chunk;       /* ROMix iterations per kernel launch */
    size_t              cap;         /* lanes per batch */
    unsigned char      *pwbuf;       /* cap * GPU_MAXPW */
    cl_uint            *lens;
    mpz_t              *idxs;        /* member index per lane, for reporting */
    unsigned char      *gout;        /* cap * 64 */
    size_t              count;       /* lanes filled in the current batch */
    unsigned long       tried;
    unsigned long       toolong;     /* skipped: passphrase > GPU_MAXPW */
    int                 found;
    char                pass[512];
    char                wif[64];
    mpz_t               hitidx;
    double              t_gpu;       /* seconds spent in gpu_run */
};

/* Run the current batch through the GPU and verify each lane. Returns 1 if a
 * hit was recorded (caller should stop). */
static int gpu_flush(struct gpu_crack *c)
{
    if (c->count == 0) return 0;
    double t0 = now_sec();
    if (gpu_run_phased(c->g, c->pwbuf, c->lens, c->count, c->key->addrhash,
                       c->N, c->chunk, c->gout) != 0)
        return 0;
    c->t_gpu += now_sec() - t0;
    c->tried += c->count;
    for (size_t l = 0; l < c->count; l++) {
        unsigned char priv[32];
        bip38_finish(c->key, c->gout + l * 64, priv);
        if (address_matches(priv, c->key->compressed, c->key->addrhash)) {
            size_t n = c->lens[l] < sizeof c->pass - 1 ? c->lens[l] : sizeof c->pass - 1;
            memcpy(c->pass, c->pwbuf + l * GPU_MAXPW, n); c->pass[n] = '\0';
            privkey_to_wif(priv, c->key->compressed, c->wif);
            mpz_set(c->hitidx, c->idxs[l]);
            c->found = 1;
            c->count = 0;
            return 1;
        }
    }
    c->count = 0;
    return 0;
}

static int gpu_crack_sink(const char *str, size_t len, const mpz_t index, void *v)
{
    struct gpu_crack *c = v;
    if (len > GPU_MAXPW) { c->toolong++; return 0; }   /* GPU handles <= MAXPW */
    size_t l = c->count;
    memcpy(c->pwbuf + l * GPU_MAXPW, str, len);
    c->lens[l] = (cl_uint)len;
    mpz_set(c->idxs[l], index);
    c->count++;
    if (c->count == c->cap) return gpu_flush(c);       /* full -> run + verify */
    return 0;
}

static int crack_gpu(const struct bip38 *key, const char *pattern,
                     size_t batch, cl_uint N, int progress)
{
    struct rxe *rxe = rxe_parse(pattern, 0);
    if (!rxe || rxe_error(rxe)) {
        fprintf(stderr, "rxe38: bad passphrase regex: %s\n",
                rxe ? rxe_error_message(rxe) : "parse failed");
        if (rxe) rxe_free(rxe);
        return 2;
    }

    struct gpu g;
    if (gpu_setup(&g, batch) != 0) { rxe_free(rxe); return 1; }
    fprintf(stderr, "rxe38 gpu: device = %s, batch = %zu lanes (%.1f GB scratchpad), N = %u\n",
            g.devname, batch, batch * (double)GPU_BLK * GPU_N / 1e9, N);
    if (N == GPU_N)
        fprintf(stderr, "rxe38 gpu: heads-up -- on a display GPU the per-lane scrypt may "
                        "exceed the watchdog; a headless card is the target.\n");

    /* Chunk size: bound work per launch to ~CHUNK*batch blockmixes so a single
     * submit stays short (watchdog-safe). Tunable via RXE38_GPU_CHUNK. */
    cl_uint chunk;
    const char *cs = getenv("RXE38_GPU_CHUNK");
    if (cs) chunk = (cl_uint)strtoul(cs, 0, 0);
    else {
        /* Bound work per launch to stay well under a display watchdog. The Arc
         * hangs at ~2^18 blockmixes/launch (~12 s), so target 2^15 (~1.5 s) for
         * margin. On a headless card raise RXE38_GPU_CHUNK for fewer launches. */
        cl_ulong target = 1u << 15;
        chunk = (cl_uint)(target / (batch ? batch : 1));
        if (chunk < 1) chunk = 1;
        if (chunk > N) chunk = N;
    }
    fprintf(stderr, "rxe38 gpu: chunk = %u iterations/launch (%llu blockmixes/launch)\n",
            chunk, (unsigned long long)chunk * batch);

    struct gpu_crack c;
    memset(&c, 0, sizeof c);
    c.g = &g; c.key = key; c.N = N; c.chunk = chunk; c.cap = batch;
    c.pwbuf = calloc(batch, GPU_MAXPW);
    c.lens  = calloc(batch, sizeof *c.lens);
    c.gout  = calloc(batch, 64);
    c.idxs  = calloc(batch, sizeof *c.idxs);
    for (size_t i = 0; i < batch; i++) mpz_init(c.idxs[i]);
    mpz_init(c.hitidx);

    double t0 = now_sec();
    mpz_t from, cnt; mpz_init_set_ui(from, 0); mpz_init_set_ui(cnt, 0);  /* whole set */
    rxe_foreach(rxe, from, cnt, GPU_MAXPW + 1, gpu_crack_sink, &c);
    if (!c.found) gpu_flush(&c);                        /* trailing partial batch */
    double dt = now_sec() - t0;
    mpz_clear(from); mpz_clear(cnt);

    int rc;
    if (c.found) {
        printf("FOUND passphrase: %s\n", c.pass);
        printf("WIF: %s\n", c.wif);
        gmp_printf("index: %Zd   (%lu tried, %.1fs wall, %.1fs gpu, %.1f cand/s)\n",
                   c.hitidx, c.tried, dt, c.t_gpu, dt > 0 ? c.tried / dt : 0);
        rc = 0;
    } else {
        fprintf(stderr, "rxe38: not found (%lu tried, %.1fs, %.1f cand/s)\n",
                c.tried, dt, dt > 0 ? c.tried / dt : 0);
        rc = 1;
    }
    if (c.toolong)
        fprintf(stderr, "rxe38 gpu: skipped %lu candidate(s) longer than %d bytes\n",
                c.toolong, GPU_MAXPW);

    for (size_t i = 0; i < batch; i++) mpz_clear(c.idxs[i]);
    mpz_clear(c.hitidx);
    free(c.pwbuf); free(c.lens); free(c.gout); free(c.idxs);
    gpu_teardown(&g);
    rxe_free(rxe);
    return rc;
}
#endif /* RXE38_GPU */

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--test-scrypt") == 0)
        return test_scrypt();
    if (argc >= 2 && strcmp(argv[1], "--test-priv") == 0)
        return test_priv();
    if (argc >= 2 && strcmp(argv[1], "--test-verify") == 0)
        return test_verify();
#ifdef RXE38_GPU
    if (argc >= 2 && strcmp(argv[1], "--gpu-scrypt-test") == 0)
        return gpu_scrypt_test(argc >= 3 ? (cl_uint)strtoul(argv[2], 0, 0) : 512);
    if (argc >= 2 && strcmp(argv[1], "--gpu-phase-test") == 0)
        return gpu_phase_test(argc >= 3 ? (cl_uint)strtoul(argv[2], 0, 0) : 512,
                              argc >= 4 ? (cl_uint)strtoul(argv[3], 0, 0) : 0);
#endif

    int jobs = 1, progress = 0, use_gpu = 0;
    long cap = 0, batch = 0;
    int i = 1;
    for (; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
        char c = argv[i][1];
        if (c == 'p') { progress = 1; continue; }        /* takes no value */
        if (c == 'G') { use_gpu = 1; continue; }         /* takes no value */
        const char *val = argv[i][2] ? argv[i] + 2       /* -j4  */
                        : (i + 1 < argc ? argv[++i] : ""); /* -j 4 */
        if (c == 'j')      jobs = atoi(val);
        else if (c == 'c') cap  = atol(val);
        else if (c == 'b') batch = atol(val);
        else {
            fprintf(stderr, "rxe38: unknown option -%c\n", c);
            return 2;
        }
    }

    if (i >= argc) {
        fprintf(stderr,
            "usage: %s [-j jobs] [-G] [-b batch] [-p] [-c count] <6P...key> [<regex>]\n"
            "  With a regex, tries each passphrase in the set until the key\n"
            "  decrypts (verified against its address hash). Without one, just\n"
            "  parses and dumps the key. no-EC-multiply keys (6PR.../6PY...) only.\n"
            "  -G uses the OpenCL GPU backend (scrypt on device, verify on host);\n"
            "  -b sets the GPU batch size in lanes (each lane needs ~16 MB).\n",
            argv[0]);
        return 2;
    }

    struct bip38 b;
    if (bip38_parse(argv[i], &b) != 0) return 1;
    const char *pattern = (i + 1 < argc) ? argv[i + 1] : NULL;

    if (!pattern) {                                 /* parse-and-dump mode */
        printf("prefix:     0142 (no-EC-multiply)\n");
        printf("compressed: %s\n", b.compressed ? "yes" : "no");
        hex("addrhash:   ", b.addrhash, 4);
        hex("enc1:       ", b.enc1, 16);
        hex("enc2:       ", b.enc2, 16);
        return 0;
    }

    if (use_gpu) {
#ifdef RXE38_GPU
        size_t bt = batch > 0 ? (size_t)batch : 64;      /* default 64 lanes */
        const char *ns = getenv("RXE38_GPU_N");          /* override N for testing */
        cl_uint N = ns ? (cl_uint)strtoul(ns, 0, 0) : GPU_N;
        return crack_gpu(&b, pattern, bt, N, progress);
#else
        fprintf(stderr, "rxe38: -G needs the GPU build (make rxe38-gpu)\n");
        return 2;
#endif
    }

    (void)batch;                        /* only consumed by the -G path above */
    if (jobs < 1) jobs = 1;
    return crack(&b, pattern, jobs, progress, cap);
}
