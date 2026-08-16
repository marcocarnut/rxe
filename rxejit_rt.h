/*
 * rxejit runtime -- helpers the generated enumerator links in line.
 *
 * This is embedded into rxejit at build time (turned into a C string by a
 * Makefile rule) and written verbatim into every generated program that needs
 * it, so the emitted C stays self-contained: -S shows the whole mechanism, and
 * the compiled binary depends on nothing but the standard library. It is kept
 * here as ordinary C -- compilable, testable -- rather than as string literals
 * inside rxejit's codegen, which would be unmaintainable.
 *
 * What lives here is what the per-item sinks share. For match: FNV and a
 * read-only set of the target strings, built once before the threads run and
 * only read after, so no thread needs a lock to probe it. Dedup, when it lands,
 * extends the set with per-thread arenas and a merge.
 *
 *          (C) 2011 Marco "Kiko" Carnut <kiko at postcogito dot org>, GPLv2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* FNV-1a, 64-bit, over n bytes. */
static unsigned long long rt_fnv(const unsigned char *s, unsigned long n)
{
    unsigned long long h = 1469598103934665603ULL;
    for (unsigned long i = 0; i < n; i++) { h ^= s[i]; h *= 1099511628211ULL; }
    return h;
}

/* A read-only set of byte strings -- the targets to match against. Open
 * addressing; the strings themselves live in 'store', the file read whole and
 * split in place. Built once, then only read, so probing is lock-free. */
struct rt_set {
    const char         **key;
    unsigned long       *len;
    unsigned long long  *hash;
    unsigned long        cap;      /* a power of two */
    char                *store;    /* the file's bytes, NUL-split */
};

static int rt_set_init(struct rt_set *s, unsigned long expect)
{
    unsigned long cap = 1024;
    while (cap * 7 <= expect * 10) cap *= 2;
    s->cap   = cap;
    s->store = NULL;
    s->key   = calloc(cap, sizeof *s->key);
    s->len   = calloc(cap, sizeof *s->len);
    s->hash  = calloc(cap, sizeof *s->hash);
    return s->key && s->len && s->hash;
}

static void rt_set_add(struct rt_set *s, const char *k, unsigned long n)
{
    unsigned long long h = rt_fnv((const unsigned char *)k, n);
    unsigned long i = (unsigned long)h & (s->cap - 1);
    while (s->key[i]) {
        if (s->hash[i] == h && s->len[i] == n && memcmp(s->key[i], k, n) == 0)
            return;                                    /* a repeated target */
        i = (i + 1) & (s->cap - 1);
    }
    s->key[i] = k; s->len[i] = n; s->hash[i] = h;
}

static int rt_set_has(const struct rt_set *s, const char *k, unsigned long n)
{
    unsigned long long h = rt_fnv((const unsigned char *)k, n);
    unsigned long i = (unsigned long)h & (s->cap - 1);
    while (s->key[i]) {
        if (s->hash[i] == h && s->len[i] == n && memcmp(s->key[i], k, n) == 0)
            return 1;
        i = (i + 1) & (s->cap - 1);
    }
    return 0;
}

/* Read a file, one target per line (a trailing CR/LF trimmed, blank lines
 * skipped), into the set. Returns 0 on success, -1 on any failure. */
static int rt_load(struct rt_set *s, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    char *buf = malloc((unsigned long)sz + 1);
    if (!buf) { fclose(f); return -1; }
    unsigned long got = fread(buf, 1, (unsigned long)sz, f);
    fclose(f);
    buf[got] = 0;

    unsigned long lines = 1;
    for (unsigned long i = 0; i < got; i++) if (buf[i] == '\n') lines++;
    if (!rt_set_init(s, lines)) { free(buf); return -1; }
    s->store = buf;

    unsigned long start = 0;
    for (unsigned long i = 0; i <= got; i++) {
        if (i == got || buf[i] == '\n') {
            unsigned long e = i;
            while (e > start && buf[e - 1] == '\r') e--;
            if (e > start) rt_set_add(s, buf + start, e - start);
            start = i + 1;
        }
    }
    return 0;
}

static void rt_set_free(struct rt_set *s)
{
    free(s->key); free(s->len); free(s->hash); free(s->store);
}

/* ---- MD5, for keycracking -------------------------------------------------
 * The candidate is hashed and its digest looked up in the target set, so the
 * targets are hashes of unknown plaintexts and a hit is a crack. RFC 1321,
 * whole-message (candidates are short), no allocation on the hot path: full
 * 64-byte blocks are consumed in place and only the tail is padded in a local
 * buffer. rt_md5 needs unsigned int to be 32 bits, which it is everywhere here.
 */

#define RT_ROTL(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

static void rt_md5_block(unsigned int abcd[4], const unsigned char *p)
{
    static const unsigned int K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
    static const unsigned char S[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
    unsigned int M[16];
    for (int i = 0; i < 16; i++)
        M[i] =  (unsigned int)p[i*4]
             | ((unsigned int)p[i*4+1] << 8)
             | ((unsigned int)p[i*4+2] << 16)
             | ((unsigned int)p[i*4+3] << 24);
    unsigned int A = abcd[0], B = abcd[1], C = abcd[2], D = abcd[3];
    for (int i = 0; i < 64; i++) {
        unsigned int F; int g;
        if      (i < 16) { F = (B & C) | (~B & D);        g = i;             }
        else if (i < 32) { F = (D & B) | (~D & C);        g = (5*i + 1) & 15; }
        else if (i < 48) { F = B ^ C ^ D;                 g = (3*i + 5) & 15; }
        else             { F = C ^ (B | ~D);              g = (7*i)     & 15; }
        F += A + K[i] + M[g];
        A = D; D = C; C = B; B += RT_ROTL(F, S[i]);
    }
    abcd[0] += A; abcd[1] += B; abcd[2] += C; abcd[3] += D;
}

static void rt_md5(const unsigned char *msg, unsigned long len, unsigned char out[16])
{
    unsigned int abcd[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    unsigned long i = 0;
    for (; i + 64 <= len; i += 64) rt_md5_block(abcd, msg + i);

    unsigned char tail[128];
    memset(tail, 0, sizeof tail);
    unsigned long r = len - i;
    memcpy(tail, msg + i, r);
    tail[r] = 0x80;
    unsigned long padlen = r < 56 ? 64 : 128;
    unsigned long long bits = (unsigned long long)len * 8;
    for (int k = 0; k < 8; k++) tail[padlen - 8 + k] = (unsigned char)((bits >> (8*k)) & 0xff);
    rt_md5_block(abcd, tail);
    if (padlen == 128) rt_md5_block(abcd, tail + 64);

    for (int k = 0; k < 4; k++) {
        out[k*4]   = (unsigned char)(abcd[k]        & 0xff);
        out[k*4+1] = (unsigned char)((abcd[k] >> 8) & 0xff);
        out[k*4+2] = (unsigned char)((abcd[k] >> 16)& 0xff);
        out[k*4+3] = (unsigned char)((abcd[k] >> 24)& 0xff);
    }
}

/* ---- MD4 / NTLM, for keycracking ------------------------------------------
 * NTLM is the Windows password hash: MD4 (RFC 1320) of the password in
 * UTF-16LE. MD4 shares MD5's little-endian word layout but runs three rounds of
 * sixteen with its own functions and shifts; the block below is the classic
 * unrolled form. rt_ntlm widens each candidate byte to a UTF-16LE code unit
 * (ASCII in, high byte zero) on the fly and feeds it to the same block loop, so
 * no widened copy of the message is ever materialised.
 */
static void rt_md4_block(unsigned int abcd[4], const unsigned char *p)
{
    unsigned int M[16];
    for (int i = 0; i < 16; i++)
        M[i] =  (unsigned int)p[i*4]
             | ((unsigned int)p[i*4+1] << 8)
             | ((unsigned int)p[i*4+2] << 16)
             | ((unsigned int)p[i*4+3] << 24);
    unsigned int a = abcd[0], b = abcd[1], c = abcd[2], d = abcd[3];
#define MD4_F(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define MD4_G(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x,y,z) ((x) ^ (y) ^ (z))
#define MD4_FF(a,b,c,d,k,s) (a) = RT_ROTL((a) + MD4_F(b,c,d) + M[k], s)
#define MD4_GG(a,b,c,d,k,s) (a) = RT_ROTL((a) + MD4_G(b,c,d) + M[k] + 0x5a827999u, s)
#define MD4_HH(a,b,c,d,k,s) (a) = RT_ROTL((a) + MD4_H(b,c,d) + M[k] + 0x6ed9eba1u, s)
    MD4_FF(a,b,c,d,0,3);  MD4_FF(d,a,b,c,1,7);  MD4_FF(c,d,a,b,2,11);  MD4_FF(b,c,d,a,3,19);
    MD4_FF(a,b,c,d,4,3);  MD4_FF(d,a,b,c,5,7);  MD4_FF(c,d,a,b,6,11);  MD4_FF(b,c,d,a,7,19);
    MD4_FF(a,b,c,d,8,3);  MD4_FF(d,a,b,c,9,7);  MD4_FF(c,d,a,b,10,11); MD4_FF(b,c,d,a,11,19);
    MD4_FF(a,b,c,d,12,3); MD4_FF(d,a,b,c,13,7); MD4_FF(c,d,a,b,14,11); MD4_FF(b,c,d,a,15,19);
    MD4_GG(a,b,c,d,0,3);  MD4_GG(d,a,b,c,4,5);  MD4_GG(c,d,a,b,8,9);   MD4_GG(b,c,d,a,12,13);
    MD4_GG(a,b,c,d,1,3);  MD4_GG(d,a,b,c,5,5);  MD4_GG(c,d,a,b,9,9);   MD4_GG(b,c,d,a,13,13);
    MD4_GG(a,b,c,d,2,3);  MD4_GG(d,a,b,c,6,5);  MD4_GG(c,d,a,b,10,9);  MD4_GG(b,c,d,a,14,13);
    MD4_GG(a,b,c,d,3,3);  MD4_GG(d,a,b,c,7,5);  MD4_GG(c,d,a,b,11,9);  MD4_GG(b,c,d,a,15,13);
    MD4_HH(a,b,c,d,0,3);  MD4_HH(d,a,b,c,8,9);  MD4_HH(c,d,a,b,4,11);  MD4_HH(b,c,d,a,12,15);
    MD4_HH(a,b,c,d,2,3);  MD4_HH(d,a,b,c,10,9); MD4_HH(c,d,a,b,6,11);  MD4_HH(b,c,d,a,14,15);
    MD4_HH(a,b,c,d,1,3);  MD4_HH(d,a,b,c,9,9);  MD4_HH(c,d,a,b,5,11);  MD4_HH(b,c,d,a,13,15);
    MD4_HH(a,b,c,d,3,3);  MD4_HH(d,a,b,c,11,9); MD4_HH(c,d,a,b,7,11);  MD4_HH(b,c,d,a,15,15);
#undef MD4_F
#undef MD4_G
#undef MD4_H
#undef MD4_FF
#undef MD4_GG
#undef MD4_HH
    abcd[0] += a; abcd[1] += b; abcd[2] += c; abcd[3] += d;
}

/* out[16] = MD4(UTF-16LE(msg)). The widened stream is elen = 2*len bytes: even
 * positions carry a candidate byte, odd positions the zero high byte. Full
 * blocks are generated straight from the source; only the tail is padded. */
static void rt_ntlm(const unsigned char *msg, unsigned long len, unsigned char out[16])
{
    unsigned int abcd[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    unsigned long elen = len * 2;
    unsigned char blk[64];
    unsigned long i = 0;                          /* widened bytes consumed */
    while (i + 64 <= elen) {
        for (int k = 0; k < 64; k++) {
            unsigned long e = i + k;
            blk[k] = (e & 1) ? 0 : msg[e >> 1];
        }
        rt_md4_block(abcd, blk);
        i += 64;
    }
    unsigned char tail[128];
    memset(tail, 0, sizeof tail);
    unsigned long r = elen - i;
    for (unsigned long k = 0; k < r; k++) {
        unsigned long e = i + k;
        tail[k] = (e & 1) ? 0 : msg[e >> 1];
    }
    tail[r] = 0x80;
    unsigned long padlen = r < 56 ? 64 : 128;
    unsigned long long bits = (unsigned long long)elen * 8;
    for (int k = 0; k < 8; k++) tail[padlen - 8 + k] = (unsigned char)((bits >> (8*k)) & 0xff);
    rt_md4_block(abcd, tail);
    if (padlen == 128) rt_md4_block(abcd, tail + 64);

    for (int k = 0; k < 4; k++) {
        out[k*4]   = (unsigned char)(abcd[k]        & 0xff);
        out[k*4+1] = (unsigned char)((abcd[k] >> 8) & 0xff);
        out[k*4+2] = (unsigned char)((abcd[k] >> 16)& 0xff);
        out[k*4+3] = (unsigned char)((abcd[k] >> 24)& 0xff);
    }
}

/* ---- SHA-1, for keycracking -----------------------------------------------
 * RFC 3174, whole-message, no allocation on the hot path. Unlike MD5/MD4 the
 * words and the digest are big-endian, and it runs eighty rounds of a single
 * mixing function selected by the round quarter. 20-byte digest. */
static void rt_sha1_block(unsigned int h[5], const unsigned char *p)
{
    unsigned int w[80];
    for (int i = 0; i < 16; i++)
        w[i] =  ((unsigned int)p[i*4]   << 24)
             |  ((unsigned int)p[i*4+1] << 16)
             |  ((unsigned int)p[i*4+2] << 8)
             |   (unsigned int)p[i*4+3];
    for (int i = 16; i < 80; i++)
        w[i] = RT_ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    unsigned int a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        unsigned int f, k;
        if      (i < 20) { f = (b & c) | (~b & d);            k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8f1bbcdc; }
        else             { f = b ^ c ^ d;                     k = 0xca62c1d6; }
        unsigned int t = RT_ROTL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = RT_ROTL(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

static void rt_sha1(const unsigned char *msg, unsigned long len, unsigned char out[20])
{
    unsigned int h[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
    unsigned long i = 0;
    for (; i + 64 <= len; i += 64) rt_sha1_block(h, msg + i);

    unsigned char tail[128];
    memset(tail, 0, sizeof tail);
    unsigned long r = len - i;
    memcpy(tail, msg + i, r);
    tail[r] = 0x80;
    unsigned long padlen = r < 56 ? 64 : 128;
    unsigned long long bits = (unsigned long long)len * 8;
    for (int k = 0; k < 8; k++) tail[padlen - 1 - k] = (unsigned char)((bits >> (8*k)) & 0xff);
    rt_sha1_block(h, tail);
    if (padlen == 128) rt_sha1_block(h, tail + 64);

    for (int k = 0; k < 5; k++) {
        out[k*4]   = (unsigned char)((h[k] >> 24) & 0xff);
        out[k*4+1] = (unsigned char)((h[k] >> 16) & 0xff);
        out[k*4+2] = (unsigned char)((h[k] >> 8)  & 0xff);
        out[k*4+3] = (unsigned char)( h[k]        & 0xff);
    }
}

/* Load a file of hex digests, one per line, into the set as raw bytes: each
 * line must be exactly 2*dglen hex characters, decoded in place (the decoded
 * bytes are shorter, so they fit over the front of the line). Malformed lines
 * are skipped. Returns 0 on success. */
static int rt_hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int rt_load_hashes(struct rt_set *s, const char *path, int dglen)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    char *buf = malloc((unsigned long)sz + 1);
    if (!buf) { fclose(f); return -1; }
    unsigned long got = fread(buf, 1, (unsigned long)sz, f);
    fclose(f);
    buf[got] = 0;

    unsigned long lines = 1;
    for (unsigned long i = 0; i < got; i++) if (buf[i] == '\n') lines++;
    if (!rt_set_init(s, lines)) { free(buf); return -1; }
    s->store = buf;

    unsigned long start = 0;
    for (unsigned long i = 0; i <= got; i++) {
        if (i == got || buf[i] == '\n') {
            unsigned long e = i;
            while (e > start && buf[e - 1] == '\r') e--;
            if ((long)(e - start) == 2 * dglen) {
                int ok = 1;
                for (int k = 0; k < dglen; k++) {
                    int hi = rt_hexval((unsigned char)buf[start + 2*k]);
                    int lo = rt_hexval((unsigned char)buf[start + 2*k + 1]);
                    if (hi < 0 || lo < 0) { ok = 0; break; }
                    buf[start + k] = (char)((hi << 4) | lo);
                }
                if (ok) rt_set_add(s, buf + start, (unsigned long)dglen);
            }
            start = i + 1;
        }
    }
    return 0;
}

/* ---- a bump arena + a growing multiset, for the dedup sink ----------------
 * Each thread dedups its shard into its own rt_dup, so the hot loop shares
 * nothing and needs no lock; the sets are merged once, at the join. The members
 * are only ever added, never freed one at a time, so a stack of big blocks
 * handed out by the byte holds them: one malloc per block, the stack freed
 * together. */

#define RT_BLOCK (1u << 20)

struct rt_arena { char *cur, *end; char **block; unsigned long nblock, cblock; };

static char *rt_arena_dup(struct rt_arena *a, const char *s, unsigned long n)
{
    if ((unsigned long)(a->end - a->cur) < n) {
        unsigned long sz = n > RT_BLOCK ? n : RT_BLOCK;
        char *b = malloc(sz);
        if (!b) return NULL;
        if (a->nblock == a->cblock) {
            unsigned long nc = a->cblock ? a->cblock * 2 : 8;
            char **nb = realloc(a->block, nc * sizeof *nb);
            if (!nb) { free(b); return NULL; }
            a->block = nb; a->cblock = nc;
        }
        a->block[a->nblock++] = b;
        a->cur = b; a->end = b + sz;
    }
    char *p = a->cur;
    memcpy(p, s, n);
    a->cur += n;
    return p;
}

static void rt_arena_free(struct rt_arena *a)
{
    for (unsigned long i = 0; i < a->nblock; i++) free(a->block[i]);
    free(a->block);
}

struct rt_ent { char *key; unsigned long len; unsigned long long hash, mult; };

struct rt_dup {
    struct rt_ent      *slot;
    unsigned long       cap, used;   /* cap a power of two; used = distinct */
    unsigned long long  total;       /* members added, repeats and all */
    struct rt_arena     arena;
    int                 oom;
};

static int rt_dup_init(struct rt_dup *d)
{
    d->cap = 1024; d->used = 0; d->total = 0; d->oom = 0;
    d->arena = (struct rt_arena){ 0 };
    d->slot = calloc(d->cap, sizeof *d->slot);
    return d->slot != NULL;
}

static void rt_dup_place(struct rt_ent *slot, unsigned long cap, struct rt_ent e)
{
    unsigned long i = (unsigned long)e.hash & (cap - 1);
    while (slot[i].key) i = (i + 1) & (cap - 1);
    slot[i] = e;
}

static int rt_dup_grow(struct rt_dup *d)
{
    unsigned long ncap = d->cap * 2;
    struct rt_ent *ns = calloc(ncap, sizeof *ns);
    if (!ns) return 0;
    for (unsigned long i = 0; i < d->cap; i++)
        if (d->slot[i].key) rt_dup_place(ns, ncap, d->slot[i]);
    free(d->slot);
    d->slot = ns; d->cap = ncap;
    return 1;
}

/* Add a member: count it, and if its spelling is new store a copy, else bump the
 * one already there. */
static void rt_dup_add(struct rt_dup *d, const char *s, unsigned long n)
{
    d->total++;
    if (d->oom) return;
    if (d->used * 10 >= d->cap * 7 && !rt_dup_grow(d)) { d->oom = 1; return; }
    unsigned long long h = rt_fnv((const unsigned char *)s, n);
    unsigned long i = (unsigned long)h & (d->cap - 1);
    while (d->slot[i].key) {
        if (d->slot[i].hash == h && d->slot[i].len == n &&
            memcmp(d->slot[i].key, s, n) == 0) { d->slot[i].mult++; return; }
        i = (i + 1) & (d->cap - 1);
    }
    char *c = rt_arena_dup(&d->arena, s, n);
    if (!c) { d->oom = 1; return; }
    d->slot[i].key = c; d->slot[i].len = n; d->slot[i].hash = h; d->slot[i].mult = 1;
    d->used++;
}

/* Fold one thread's set into a master, summing multiplicity -- a member distinct
 * within a shard is still a duplicate if another shard rendered it. The bytes
 * are borrowed, not copied, so the source must outlive the merge. */
static void rt_dup_absorb(struct rt_dup *m, const struct rt_dup *o)
{
    m->total += o->total;
    if (o->oom) m->oom = 1;
    for (unsigned long i = 0; i < o->cap; i++) {
        if (!o->slot[i].key) continue;
        if (m->used * 10 >= m->cap * 7 && !rt_dup_grow(m)) { m->oom = 1; return; }
        struct rt_ent e = o->slot[i];
        unsigned long j = (unsigned long)e.hash & (m->cap - 1);
        while (m->slot[j].key) {
            if (m->slot[j].hash == e.hash && m->slot[j].len == e.len &&
                memcmp(m->slot[j].key, e.key, e.len) == 0) { m->slot[j].mult += e.mult; break; }
            j = (j + 1) & (m->cap - 1);
        }
        if (!m->slot[j].key) { m->slot[j] = e; m->used++; }
    }
}

static void rt_dup_free(struct rt_dup *d)
{
    rt_arena_free(&d->arena);
    free(d->slot);
}
