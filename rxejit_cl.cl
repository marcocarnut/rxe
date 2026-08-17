/* rxejit_cl.cl - the device-side runtime for the -G (OpenCL) backend.
 *
 * The reusable half of a generated GPU kernel: the keycracking hashes -- MD5
 * (RFC 1321), NTLM = MD4 (RFC 1320) of UTF-16LE, and SHA-1 (RFC 3174) -- and a
 * binary search over the sorted target digests. rxejit emits the pattern-specific
 * half after this -- the __constant wheel alphabets and the crack() kernel that
 * unranks a lane's index into a candidate, hashes it, and appends a hit. Kept
 * as real OpenCL C so it can be read and checked on its own; the Makefile turns
 * it into a C string the generated host program hands to clBuildProgram.
 *
 * Same constants and rounds as rt_md5 in rxejit_rt.h, so a lane's digest is
 * bit-identical to the CPU's -- the CPU stays the oracle. The one difference is
 * for speed: the 16 message words are built straight from the candidate and the
 * pad (not through a byte buffer) and the rounds are unrolled, so when the
 * candidate length is a compile-time constant -- the baked fixed path -- the ~11
 * words that are pure padding/length fold into the round constants and never
 * occupy a register, which lifts occupancy on a register-starved GPU.
 */

#define CL_ROTL(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define CL_ROTR(x, c) (((x) >> (c)) | ((x) << (32 - (c))))

/* Unrolling the 64 rounds turns g / CLK[i] / CLS[i] into constants and folds a
 * fixed-length candidate's constant message words into the round adds -- a win
 * on Intel NEO. On a register-starved GPU the code bloat can cost more than it
 * saves, so it is a knob: rxejit passes -D RXEJIT_UNROLL=0 when RXEJIT_NO_UNROLL
 * is set in the environment, to A/B it per device. */
#ifndef RXEJIT_UNROLL
#define RXEJIT_UNROLL 1
#endif
#if RXEJIT_UNROLL
#define MD5_UNROLL _Pragma("unroll")
#else
#define MD5_UNROLL
#endif

__constant uint  CLK[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
__constant uchar CLS[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };

/* Compress one already-assembled 16-word message block. Taking the words
 * directly (not a byte buffer) lets a caller with constant words -- the padding
 * and length of a fixed-length candidate -- have them folded into the rounds. */
static void cl_md5_block(uint abcd[4], const uint M[16])
{
    uint A = abcd[0], B = abcd[1], C = abcd[2], D = abcd[3];
    MD5_UNROLL
    for (int i = 0; i < 64; i++) {
        uint F; int g;
        if      (i < 16) { F = (B & C) | (~B & D);  g = i;              }
        else if (i < 32) { F = (D & B) | (~D & C);  g = (5*i + 1) & 15; }
        else if (i < 48) { F = B ^ C ^ D;           g = (3*i + 5) & 15; }
        else             { F = C ^ (B | ~D);        g = (7*i)     & 15; }
        F += A + CLK[i] + M[g];
        A = D; D = C; C = B; B += CL_ROTL(F, CLS[i]);
    }
    abcd[0] += A; abcd[1] += B; abcd[2] += C; abcd[3] += D;
}

/* A candidate is a mask width -- short -- so its padded message is one block
 * (len < 56). The message words are built straight from the candidate and the
 * pad, not through a 64-byte buffer: when len is a compile-time constant (the
 * baked fixed path) every word past the candidate is a constant the compiler
 * folds into the round, and never lives in a register. */
static void cl_md5_abcd(const uchar *msg, uint len, uint abcd[4])
{
    abcd[0] = 0x67452301; abcd[1] = 0xefcdab89; abcd[2] = 0x98badcfe; abcd[3] = 0x10325476;
    uint M[16];
#pragma unroll
    for (int w = 0; w < 14; w++) {
        uint word = 0;
#pragma unroll
        for (int t = 0; t < 4; t++) {
            uint pos = (uint)(w * 4 + t);
            uint b = pos < len ? msg[pos] : (pos == len ? 0x80u : 0u);
            word |= b << (8 * t);
        }
        M[w] = word;
    }
    M[14] = len * 8;                   /* one block: bit length fits 32 bits */
    M[15] = 0;
    cl_md5_block(abcd, M);
}
static void cl_md5(const uchar *msg, uint len, uchar out[16])
{
    uint abcd[4];
    cl_md5_abcd(msg, len, abcd);
    for (int k = 0; k < 4; k++) {
        out[k*4]   = (uchar)(abcd[k]        & 0xff);
        out[k*4+1] = (uchar)((abcd[k] >> 8) & 0xff);
        out[k*4+2] = (uchar)((abcd[k] >> 16)& 0xff);
        out[k*4+3] = (uchar)((abcd[k] >> 24)& 0xff);
    }
}
/* The digest's first 32-bit word, big-endian (its first four bytes as a word).
 * Only abcd[0] is read, so the compiler drops the rounds that finalise the rest
 * -- a cheap early reject the host confirms by re-hashing. */
static uint cl_be(uint x) { return (x << 24) | ((x & 0xff00u) << 8) | ((x >> 8) & 0xff00u) | (x >> 24); }
static uint cl_md5_w0(const uchar *msg, uint len)
{
    uint abcd[4];
    cl_md5_abcd(msg, len, abcd);
    return cl_be(abcd[0]);
}

/* NTLM = MD4(UTF-16LE(candidate)). MD4 (RFC 1320) shares MD5's little-endian
 * word layout but runs three rounds of sixteen with its own functions/shifts;
 * cl_md4_block is the classic unrolled form over an assembled 16-word block. */
static void cl_md4_block(uint abcd[4], const uint M[16])
{
    uint a = abcd[0], b = abcd[1], c = abcd[2], d = abcd[3];
#define M4F(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define M4G(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define M4H(x,y,z) ((x) ^ (y) ^ (z))
#define M4FF(a,b,c,d,k,s) a = CL_ROTL(a + M4F(b,c,d) + M[k], s)
#define M4GG(a,b,c,d,k,s) a = CL_ROTL(a + M4G(b,c,d) + M[k] + 0x5a827999u, s)
#define M4HH(a,b,c,d,k,s) a = CL_ROTL(a + M4H(b,c,d) + M[k] + 0x6ed9eba1u, s)
    M4FF(a,b,c,d,0,3);  M4FF(d,a,b,c,1,7);  M4FF(c,d,a,b,2,11);  M4FF(b,c,d,a,3,19);
    M4FF(a,b,c,d,4,3);  M4FF(d,a,b,c,5,7);  M4FF(c,d,a,b,6,11);  M4FF(b,c,d,a,7,19);
    M4FF(a,b,c,d,8,3);  M4FF(d,a,b,c,9,7);  M4FF(c,d,a,b,10,11); M4FF(b,c,d,a,11,19);
    M4FF(a,b,c,d,12,3); M4FF(d,a,b,c,13,7); M4FF(c,d,a,b,14,11); M4FF(b,c,d,a,15,19);
    M4GG(a,b,c,d,0,3);  M4GG(d,a,b,c,4,5);  M4GG(c,d,a,b,8,9);   M4GG(b,c,d,a,12,13);
    M4GG(a,b,c,d,1,3);  M4GG(d,a,b,c,5,5);  M4GG(c,d,a,b,9,9);   M4GG(b,c,d,a,13,13);
    M4GG(a,b,c,d,2,3);  M4GG(d,a,b,c,6,5);  M4GG(c,d,a,b,10,9);  M4GG(b,c,d,a,14,13);
    M4GG(a,b,c,d,3,3);  M4GG(d,a,b,c,7,5);  M4GG(c,d,a,b,11,9);  M4GG(b,c,d,a,15,13);
    M4HH(a,b,c,d,0,3);  M4HH(d,a,b,c,8,9);  M4HH(c,d,a,b,4,11);  M4HH(b,c,d,a,12,15);
    M4HH(a,b,c,d,2,3);  M4HH(d,a,b,c,10,9); M4HH(c,d,a,b,6,11);  M4HH(b,c,d,a,14,15);
    M4HH(a,b,c,d,1,3);  M4HH(d,a,b,c,9,9);  M4HH(c,d,a,b,5,11);  M4HH(b,c,d,a,13,15);
    M4HH(a,b,c,d,3,3);  M4HH(d,a,b,c,11,9); M4HH(c,d,a,b,7,11);  M4HH(b,c,d,a,15,15);
#undef M4F
#undef M4G
#undef M4H
#undef M4FF
#undef M4GG
#undef M4HH
    abcd[0] += a; abcd[1] += b; abcd[2] += c; abcd[3] += d;
}

/* A candidate fits one MD4 block once widened (2*len < 56, i.e. len < 28). The
 * UTF-16LE message words are built straight from the candidate: even byte
 * positions carry a candidate byte, odd positions the zero high byte, and the
 * pad/length fold into constants for a fixed length, exactly like cl_md5. */
static void cl_ntlm_abcd(const uchar *msg, uint len, uint abcd[4])
{
    abcd[0] = 0x67452301; abcd[1] = 0xefcdab89; abcd[2] = 0x98badcfe; abcd[3] = 0x10325476;
    uint elen = len * 2;
    uint M[16];
#pragma unroll
    for (int w = 0; w < 14; w++) {
        uint word = 0;
#pragma unroll
        for (int t = 0; t < 4; t++) {
            uint pos = (uint)(w * 4 + t);
            uint b = pos < elen ? ((pos & 1) ? 0u : (uint)msg[pos >> 1])
                                : (pos == elen ? 0x80u : 0u);
            word |= b << (8 * t);
        }
        M[w] = word;
    }
    M[14] = elen * 8;
    M[15] = 0;
    cl_md4_block(abcd, M);
}
static void cl_ntlm(const uchar *msg, uint len, uchar out[16])
{
    uint abcd[4];
    cl_ntlm_abcd(msg, len, abcd);
    for (int k = 0; k < 4; k++) {
        out[k*4]   = (uchar)(abcd[k]        & 0xff);
        out[k*4+1] = (uchar)((abcd[k] >> 8) & 0xff);
        out[k*4+2] = (uchar)((abcd[k] >> 16)& 0xff);
        out[k*4+3] = (uchar)((abcd[k] >> 24)& 0xff);
    }
}
static uint cl_ntlm_w0(const uchar *msg, uint len)
{
    uint abcd[4];
    cl_ntlm_abcd(msg, len, abcd);
    return cl_be(abcd[0]);
}

/* SHA-1 (RFC 3174), single block (len < 56). Big-endian words and digest, and
 * eighty rounds of a mixing function chosen by the round quarter. The first 14
 * words come straight from the candidate + pad (constant-folded at a fixed
 * length); the schedule extends them to 80. 20-byte digest. */
static void cl_sha1(const uchar *msg, uint len, uchar out[20])
{
    uint h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    uint w[80];
#pragma unroll
    for (int i = 0; i < 14; i++) {
        uint word = 0;
#pragma unroll
        for (int t = 0; t < 4; t++) {
            uint pos = (uint)(i * 4 + t);
            uint b = pos < len ? (uint)msg[pos] : (pos == len ? 0x80u : 0u);
            word = (word << 8) | b;
        }
        w[i] = word;
    }
    w[14] = 0;
    w[15] = len * 8;
    MD5_UNROLL
    for (int i = 16; i < 80; i++)
        w[i] = CL_ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    uint a = h0, b = h1, c = h2, d = h3, e = h4;
    MD5_UNROLL
    for (int i = 0; i < 80; i++) {
        uint f, k;
        if      (i < 20) { f = (b & c) | (~b & d);          k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else             { f = b ^ c ^ d;                   k = 0xca62c1d6; }
        uint t = CL_ROTL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = CL_ROTL(b, 30); b = a; a = t;
    }
    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    uint hh[5] = { h0, h1, h2, h3, h4 };
    for (int k = 0; k < 5; k++) {
        out[k*4]   = (uchar)((hh[k] >> 24) & 0xff);
        out[k*4+1] = (uchar)((hh[k] >> 16) & 0xff);
        out[k*4+2] = (uchar)((hh[k] >> 8)  & 0xff);
        out[k*4+3] = (uchar)( hh[k]        & 0xff);
    }
}

/* SHA-256 (FIPS 180-4), single block (len < 56). Big-endian words and a 32-byte
 * digest, sixty-four rounds whose schedule extends the first 16 words (candidate
 * + pad, constant-folded at a fixed length) to 64. */
__constant uint CK256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
static void cl_sha256(const uchar *msg, uint len, uchar out[32])
{
    uint h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
         h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    uint w[64];
#pragma unroll
    for (int i = 0; i < 14; i++) {
        uint word = 0;
#pragma unroll
        for (int t = 0; t < 4; t++) {
            uint pos = (uint)(i * 4 + t);
            uint b = pos < len ? (uint)msg[pos] : (pos == len ? 0x80u : 0u);
            word = (word << 8) | b;
        }
        w[i] = word;
    }
    w[14] = 0;
    w[15] = len * 8;
    MD5_UNROLL
    for (int i = 16; i < 64; i++) {
        uint s0 = CL_ROTR(w[i-15], 7) ^ CL_ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint s1 = CL_ROTR(w[i-2], 17) ^ CL_ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    MD5_UNROLL
    for (int i = 0; i < 64; i++) {
        uint S1 = CL_ROTR(e, 6) ^ CL_ROTR(e, 11) ^ CL_ROTR(e, 25);
        uint ch = (e & f) ^ (~e & g);
        uint t1 = hh + S1 + ch + CK256[i] + w[i];
        uint S0 = CL_ROTR(a, 2) ^ CL_ROTR(a, 13) ^ CL_ROTR(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    uint hh8[8] = { h0+a, h1+b, h2+c, h3+d, h4+e, h5+f, h6+g, h7+hh };
    for (int k = 0; k < 8; k++) {
        out[k*4]   = (uchar)((hh8[k] >> 24) & 0xff);
        out[k*4+1] = (uchar)((hh8[k] >> 16) & 0xff);
        out[k*4+2] = (uchar)((hh8[k] >> 8)  & 0xff);
        out[k*4+3] = (uchar)( hh8[k]        & 0xff);
    }
}

/* The targets are DGLEN-byte digests the host uploaded sorted (16 for MD5/NTLM,
 * 20 for SHA-1, 32 for SHA-256 -- baked in per build), so a lane finds its
 * digest (or not) in log2(ntgt) comparisons -- no contention, all read-only. */
#ifndef DGLEN
#define DGLEN 16
#endif
static int cl_tgt_has(__global const uchar *t, uint ntgt, const uchar dg[DGLEN])
{
    int lo = 0, hi = (int)ntgt - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        __global const uchar *e = t + (uint)mid * DGLEN;
        int c = 0;
        for (int i = 0; i < DGLEN; i++)
            if (dg[i] != e[i]) { c = dg[i] < e[i] ? -1 : 1; break; }
        if (c == 0) return 1;
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return 0;
}

/* First-word reject: is any target's first four bytes equal to w0 (big-endian)?
 * The targets are sorted by their whole digest, so also by this leading word, so
 * the same binary search works on one word. A match is only a candidate -- the
 * host re-hashes to reject the ~ntgt/2^32-per-candidate false positives. */
static int cl_tgt_has_w0(__global const uchar *t, uint ntgt, uint w0)
{
    int lo = 0, hi = (int)ntgt - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        __global const uchar *e = t + (uint)mid * DGLEN;
        uint tw = ((uint)e[0] << 24) | ((uint)e[1] << 16) | ((uint)e[2] << 8) | (uint)e[3];
        if (w0 == tw) return 1;
        if (w0 < tw) hi = mid - 1; else lo = mid + 1;
    }
    return 0;
}
