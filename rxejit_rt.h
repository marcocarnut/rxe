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
#define RT_ROTR(x, c) (((x) >> (c)) | ((x) << (32 - (c))))

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

/* ---- MD5 x8, AVX2 -- eight candidates at once -----------------------------
 * The keycrack hot path hashes one short candidate per step; MD5 has no data
 * dependence between candidates, so eight independent messages run in the eight
 * 32-bit lanes of an AVX2 register at ~one lane's cost. This is the single-block
 * compressor only: the caller bakes the 16 message words (pad byte and the
 * 64-bit length included) for each of the eight lanes -- m[word][lane] -- and
 * reads back the four digest words per lane in out[word][lane], little-endian,
 * exactly the a,b,c,d the scalar bake ends with. Plain-array in and out, so no
 * vector type crosses the ABI and a non-AVX2 caller can invoke it; the AVX2
 * itself is gated behind the target attribute and a runtime capability check.
 *
 * x86 only; other targets keep the scalar bake. Guard every use with
 * rt_has_avx2() -- true only where the instructions actually run.
 */
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>

static int rt_has_avx2(void) { return __builtin_cpu_supports("avx2"); }

__attribute__((target("avx2")))
static void rt_md5_x8(const unsigned int m[16][8], unsigned int out[4][8])
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
    __m256i M[16];
    for (int i = 0; i < 16; i++) M[i] = _mm256_loadu_si256((const __m256i *)m[i]);
    const __m256i IVA = _mm256_set1_epi32((int)0x67452301);
    const __m256i IVB = _mm256_set1_epi32((int)0xefcdab89);
    const __m256i IVC = _mm256_set1_epi32((int)0x98badcfe);
    const __m256i IVD = _mm256_set1_epi32((int)0x10325476);
    __m256i a = IVA, b = IVB, c = IVC, d = IVD;
    const __m256i ones = _mm256_cmpeq_epi32(IVA, IVA);   /* all-ones = ~0 */
    for (int i = 0; i < 64; i++) {
        __m256i F; int g;
        if      (i < 16) { F = _mm256_or_si256(_mm256_and_si256(b, c), _mm256_andnot_si256(b, d)); g = i; }
        else if (i < 32) { F = _mm256_or_si256(_mm256_and_si256(d, b), _mm256_andnot_si256(d, c)); g = (5*i + 1) & 15; }
        else if (i < 48) { F = _mm256_xor_si256(_mm256_xor_si256(b, c), d);                        g = (3*i + 5) & 15; }
        else             { F = _mm256_xor_si256(c, _mm256_or_si256(b, _mm256_xor_si256(d, ones))); g = (7*i)     & 15; }
        F = _mm256_add_epi32(F, a);
        F = _mm256_add_epi32(F, _mm256_set1_epi32((int)K[i]));
        F = _mm256_add_epi32(F, M[g]);
        int s = S[i];
        __m128i cl = _mm_cvtsi32_si128(s), cr = _mm_cvtsi32_si128(32 - s);
        __m256i rot = _mm256_or_si256(_mm256_sll_epi32(F, cl), _mm256_srl_epi32(F, cr));
        a = d; d = c; c = b; b = _mm256_add_epi32(b, rot);
    }
    _mm256_storeu_si256((__m256i *)out[0], _mm256_add_epi32(IVA, a));
    _mm256_storeu_si256((__m256i *)out[1], _mm256_add_epi32(IVB, b));
    _mm256_storeu_si256((__m256i *)out[2], _mm256_add_epi32(IVC, c));
    _mm256_storeu_si256((__m256i *)out[3], _mm256_add_epi32(IVD, d));
}

/* ---- SHA-NI, for keycracking ----------------------------------------------
 * The Intel SHA extensions accelerate ONE stream: sha256rnds2 / sha1rnds4 each
 * fold several rounds into a single instruction, so a single candidate's hash
 * costs a handful of ops instead of 64/80 unrolled rounds. Unlike md5-x8 this
 * is not eight-wide -- it makes the per-candidate hash cheap rather than doing
 * many at once. Single 64-byte block: the caller preloads state with the IV and
 * hands over the padded block; the digest is the state words on return, the
 * same big-endian a..h / a..e the scalar blocks produce. Gate every use with
 * rt_has_sha(). Canonical public-domain sequences (Gulley/Walton).
 */
static int rt_has_sha(void) { return __builtin_cpu_supports("sha"); }

__attribute__((target("sha,sse4.1")))
static void rt_sha256_ni_block(unsigned int state[8], const unsigned char data[64])
{
    __m128i STATE0, STATE1, MSG, TMP, MSG0, MSG1, MSG2, MSG3, ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    TMP    = _mm_loadu_si128((const __m128i *)&state[0]);   /* A B C D */
    STATE1 = _mm_loadu_si128((const __m128i *)&state[4]);   /* E F G H */
    TMP    = _mm_shuffle_epi32(TMP, 0xB1);                  /* C D A B */
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);              /* H G F E */
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);              /* A B E F */
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);          /* C D G H */
    ABEF_SAVE = STATE0; CDGH_SAVE = STATE1;

    MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data+0)), MASK);
    MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

    MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data+16)), MASK);
    MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data+32)), MASK);
    MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data+48)), MASK);
    MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP  = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_sha256msg2_epu32(_mm_add_epi32(MSG0, TMP), MSG3);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 16-51: current word Ma, next Mb (gets msg2), previous Md (alignr
     * source and msg1 target). The message words cycle MSG0->1->2->3->0. */
#define RT_SHA256_STEP(Ma, Mb, Md, KK) \
    MSG  = _mm_add_epi32(Ma, _mm_set_epi64x KK); \
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG); \
    TMP  = _mm_alignr_epi8(Ma, Md, 4); \
    Mb   = _mm_sha256msg2_epu32(_mm_add_epi32(Mb, TMP), Ma); \
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E)); \
    Md   = _mm_sha256msg1_epu32(Md, Ma)
    RT_SHA256_STEP(MSG0, MSG1, MSG3, (0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL)); /* 16-19 */
    RT_SHA256_STEP(MSG1, MSG2, MSG0, (0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL)); /* 20-23 */
    RT_SHA256_STEP(MSG2, MSG3, MSG1, (0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL)); /* 24-27 */
    RT_SHA256_STEP(MSG3, MSG0, MSG2, (0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL)); /* 28-31 */
    RT_SHA256_STEP(MSG0, MSG1, MSG3, (0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL)); /* 32-35 */
    RT_SHA256_STEP(MSG1, MSG2, MSG0, (0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL)); /* 36-39 */
    RT_SHA256_STEP(MSG2, MSG3, MSG1, (0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL)); /* 40-43 */
    RT_SHA256_STEP(MSG3, MSG0, MSG2, (0x106AA070F40E3585ULL, 0xD6990624D192E819ULL)); /* 44-47 */
    RT_SHA256_STEP(MSG0, MSG1, MSG3, (0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL)); /* 48-51 */
#undef RT_SHA256_STEP
    /* 52-55: msg1 no longer needed */
    MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP  = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_sha256msg2_epu32(_mm_add_epi32(MSG2, TMP), MSG1);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));
    /* 56-59 */
    MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP  = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_sha256msg2_epu32(_mm_add_epi32(MSG3, TMP), MSG2);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));
    /* 60-63 */
    MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);
    TMP    = _mm_shuffle_epi32(STATE0, 0x1B);              /* F E B A */
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);             /* D C H G */
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);         /* D C B A */
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);            /* A B E F -> H G F E */
    _mm_storeu_si128((__m128i *)&state[0], STATE0);
    _mm_storeu_si128((__m128i *)&state[4], STATE1);
}

__attribute__((target("sha,sse4.1")))
static void rt_sha1_ni_block(unsigned int state[5], const unsigned char data[64])
{
    __m128i ABCD, E0, E1, MSG0, MSG1, MSG2, MSG3, ABCD_SAVE, E0_SAVE;
    const __m128i MASK = _mm_set_epi64x(0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL);

    ABCD = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)state), 0x1B);
    E0   = _mm_set_epi32((int)state[4], 0, 0, 0);
    ABCD_SAVE = ABCD; E0_SAVE = E0;

    MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data+0)),  MASK);
    MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data+16)), MASK);
    MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data+32)), MASK);
    MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data+48)), MASK);

    E0 = _mm_add_epi32(E0, MSG0); E1 = ABCD;                              /* 0-3 */
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    E1 = _mm_sha1nexte_epu32(E1, MSG1); E0 = ABCD;                        /* 4-7 */
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0); MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    E0 = _mm_sha1nexte_epu32(E0, MSG2); E1 = ABCD;                        /* 8-11 */
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0); MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

#define RT_SHA1_STEP(Ea, Eb, Ma, Mb, Mc, Md, K) \
    Eb = _mm_sha1nexte_epu32(Eb, Md); Ea = ABCD; \
    Ma = _mm_sha1msg2_epu32(Ma, Md); \
    ABCD = _mm_sha1rnds4_epu32(ABCD, Eb, K); \
    Mc = _mm_sha1msg1_epu32(Mc, Md); Mb = _mm_xor_si128(Mb, Md)
    RT_SHA1_STEP(E0, E1, MSG0, MSG1, MSG2, MSG3, 0); /* 12-15 */
    RT_SHA1_STEP(E1, E0, MSG1, MSG2, MSG3, MSG0, 0); /* 16-19 */
    RT_SHA1_STEP(E0, E1, MSG2, MSG3, MSG0, MSG1, 1); /* 20-23 */
    RT_SHA1_STEP(E1, E0, MSG3, MSG0, MSG1, MSG2, 1); /* 24-27 */
    RT_SHA1_STEP(E0, E1, MSG0, MSG1, MSG2, MSG3, 1); /* 28-31 */
    RT_SHA1_STEP(E1, E0, MSG1, MSG2, MSG3, MSG0, 1); /* 32-35 */
    RT_SHA1_STEP(E0, E1, MSG2, MSG3, MSG0, MSG1, 1); /* 36-39 */
    RT_SHA1_STEP(E1, E0, MSG3, MSG0, MSG1, MSG2, 2); /* 40-43 */
    RT_SHA1_STEP(E0, E1, MSG0, MSG1, MSG2, MSG3, 2); /* 44-47 */
    RT_SHA1_STEP(E1, E0, MSG1, MSG2, MSG3, MSG0, 2); /* 48-51 */
    RT_SHA1_STEP(E0, E1, MSG2, MSG3, MSG0, MSG1, 2); /* 52-55 */
    RT_SHA1_STEP(E1, E0, MSG3, MSG0, MSG1, MSG2, 2); /* 56-59 */
#undef RT_SHA1_STEP
    E1 = _mm_sha1nexte_epu32(E1, MSG3); E0 = ABCD;                        /* 60-63 */
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3); MSG1 = _mm_xor_si128(MSG1, MSG3);
    E0 = _mm_sha1nexte_epu32(E0, MSG0); E1 = ABCD;                        /* 64-67 */
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0); MSG2 = _mm_xor_si128(MSG2, MSG0);
    E1 = _mm_sha1nexte_epu32(E1, MSG1); E0 = ABCD;                        /* 68-71 */
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3); MSG3 = _mm_xor_si128(MSG3, MSG1);
    E0 = _mm_sha1nexte_epu32(E0, MSG2); E1 = ABCD;                        /* 72-75 */
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
    E1 = _mm_sha1nexte_epu32(E1, MSG3); E0 = ABCD;                        /* 76-79 */
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);

    E0   = _mm_sha1nexte_epu32(E0, E0_SAVE);
    ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);
    ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
    _mm_storeu_si128((__m128i *)state, ABCD);
    state[4] = (unsigned)_mm_extract_epi32(E0, 3);
}
#else
static int rt_has_avx2(void) { return 0; }
static int rt_has_sha(void)  { return 0; }
#endif

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

/* ---- SHA-256, for keycracking ---------------------------------------------
 * FIPS 180-4: big-endian words and a 32-byte digest, sixty-four rounds whose
 * message schedule extends the sixteen block words to sixty-four. Same
 * whole-message, allocation-free shape as the others. */
static void rt_sha256_block(unsigned int h[8], const unsigned char *p)
{
    static const unsigned int K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
    unsigned int w[64];
    for (int i = 0; i < 16; i++)
        w[i] =  ((unsigned int)p[i*4]   << 24)
             |  ((unsigned int)p[i*4+1] << 16)
             |  ((unsigned int)p[i*4+2] << 8)
             |   (unsigned int)p[i*4+3];
    for (int i = 16; i < 64; i++) {
        unsigned int s0 = RT_ROTR(w[i-15], 7) ^ RT_ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
        unsigned int s1 = RT_ROTR(w[i-2], 17) ^ RT_ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    unsigned int a = h[0], b = h[1], c = h[2], d = h[3],
                 e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        unsigned int S1 = RT_ROTR(e, 6) ^ RT_ROTR(e, 11) ^ RT_ROTR(e, 25);
        unsigned int ch = (e & f) ^ (~e & g);
        unsigned int t1 = hh + S1 + ch + K[i] + w[i];
        unsigned int S0 = RT_ROTR(a, 2) ^ RT_ROTR(a, 13) ^ RT_ROTR(a, 22);
        unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
        unsigned int t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void rt_sha256(const unsigned char *msg, unsigned long len, unsigned char out[32])
{
    unsigned int h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    unsigned long i = 0;
    for (; i + 64 <= len; i += 64) rt_sha256_block(h, msg + i);

    unsigned char tail[128];
    memset(tail, 0, sizeof tail);
    unsigned long r = len - i;
    memcpy(tail, msg + i, r);
    tail[r] = 0x80;
    unsigned long padlen = r < 56 ? 64 : 128;
    unsigned long long bits = (unsigned long long)len * 8;
    for (int k = 0; k < 8; k++) tail[padlen - 1 - k] = (unsigned char)((bits >> (8*k)) & 0xff);
    rt_sha256_block(h, tail);
    if (padlen == 128) rt_sha256_block(h, tail + 64);

    for (int k = 0; k < 8; k++) {
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

/* ---- first-word pre-filter ------------------------------------------------
 * Once the hash is vectorized the target lookup is the hot cost: rt_set_has
 * runs FNV over the whole digest for a candidate that almost never matches. A
 * bitmap keyed on the digest's first four bytes rejects the misses in one load
 * and one bit test, so the full extract-and-probe runs only on the rare
 * survivor. It never drops a real hit -- every target sets its own bit, so a
 * true digest always survives -- only lets a few misses through to the exact
 * probe, which rejects them. Sized to ~32 bits per target (a few percent false
 * positives), clamped, built once before the threads run and then read-only.
 */
static unsigned      *rt_pre_bits = NULL;
static unsigned long   rt_pre_mask = 0;

static void rt_pre_build(const struct rt_set *s)
{
    unsigned long n = 0;
    for (unsigned long i = 0; i < s->cap; i++) if (s->key[i]) n++;
    unsigned long nb = 1UL << 16;
    while (nb < n * 32UL && nb < (1UL << 28)) nb <<= 1;
    rt_pre_bits = calloc(nb / 32, sizeof *rt_pre_bits);
    if (!rt_pre_bits) { rt_pre_mask = 0; return; }     /* no filter -> pass everything */
    rt_pre_mask = nb - 1;
    for (unsigned long i = 0; i < s->cap; i++)
        if (s->key[i] && s->len[i] >= 4) {
            const unsigned char *k = (const unsigned char *)s->key[i];
            unsigned fw = (unsigned)k[0] | ((unsigned)k[1] << 8)
                        | ((unsigned)k[2] << 16) | ((unsigned)k[3] << 24);
            unsigned long b = fw & rt_pre_mask;
            rt_pre_bits[b >> 5] |= 1u << (b & 31);
        }
}

/* fw is the digest's first four bytes read little-endian -- for md5/md4 that is
 * the first state word a as-is; a big-endian (sha) word is byte-swapped first. */
static inline int rt_pre_hit(unsigned fw)
{
    if (!rt_pre_bits) return 1;
    unsigned long b = fw & rt_pre_mask;
    return (rt_pre_bits[b >> 5] >> (b & 31)) & 1u;
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
    rt_pre_build(s);          /* the first-word reject filter, from the targets */
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
