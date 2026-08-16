/* rxejit_cl.cl - the device-side runtime for the -G (OpenCL) backend.
 *
 * The reusable half of a generated GPU kernel: MD5 (RFC 1321) and a binary
 * search over the sorted target digests. rxejit emits the pattern-specific
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
static void cl_md5(const uchar *msg, uint len, uchar out[16])
{
    uint abcd[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
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
    for (int k = 0; k < 4; k++) {
        out[k*4]   = (uchar)(abcd[k]        & 0xff);
        out[k*4+1] = (uchar)((abcd[k] >> 8) & 0xff);
        out[k*4+2] = (uchar)((abcd[k] >> 16)& 0xff);
        out[k*4+3] = (uchar)((abcd[k] >> 24)& 0xff);
    }
}

/* The targets are 16-byte digests the host uploaded sorted, so a lane finds its
 * digest (or not) in log2(ntgt) comparisons -- no contention, all read-only. */
static int cl_tgt_has(__global const uchar *t, uint ntgt, const uchar dg[16])
{
    int lo = 0, hi = (int)ntgt - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        __global const uchar *e = t + (uint)mid * 16;
        int c = 0;
        for (int i = 0; i < 16; i++)
            if (dg[i] != e[i]) { c = dg[i] < e[i] ? -1 : 1; break; }
        if (c == 0) return 1;
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return 0;
}
