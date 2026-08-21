/*
 * scrypt.cl -- the scrypt(N,r,p) kernel for rxe38's GPU backend (G1).
 *
 * One work-item = one candidate passphrase. Each lane computes the full
 * scrypt KDF and writes the 64-byte dh1||dh2 the host needs; the host then
 * finishes AES + secp256k1 + address-verify. scrypt is ~99.99% of the per-
 * candidate cost, so this offloads essentially all of it.
 *
 * Ported byte-for-byte from the CPU reference in rxe38.c and validated against
 * it. Block buffers are raw bytes (the exact sequence the CPU holds); Salsa20/8
 * reads/writes them as little-endian words, matching an LE host's memcpy. The
 * heavy state (V scratchpad, the p working blocks, BlockMix scratch) lives in
 * __global memory -- 16 MB/lane for BIP38's N=16384,r=8 -- since it cannot fit
 * in registers and the kernel is memory-bandwidth bound anyway.
 *
 * Compile-time: -D SN=<N> -D SR=<r> -D SP=<p> -D MAXPW=<max passphrase bytes>.
 *
 *          (C) 2026 Marco "Kiko" Carnut <kiko at postcogito dot org>, GPLv2.
 */

#define BLK   (128u * SR)        /* bytes in one scrypt block (1024 for r=8) */
#define BWORDS (32u * SR)        /* uint words in one block (256 for r=8)     */

/* ---- SHA-256 (streaming, private buffers) ------------------------------ */

typedef struct { uint h[8]; uint total; uint n; uchar buf[64]; } sctx;

__constant uint SHA_K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

#define ROR(x,n) rotate((uint)(x), (uint)(32-(n)))

static void sha_compress(uint h[8], const uchar *p)
{
    uint w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint)p[4*i]<<24)|((uint)p[4*i+1]<<16)|((uint)p[4*i+2]<<8)|p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15]>>3);
        uint s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; i++) {
        uint S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25);
        uint ch = (e & f) ^ (~e & g);
        uint t1 = hh + S1 + ch + SHA_K[i] + w[i];
        uint S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

static void sha_init(sctx *s)
{
    s->h[0]=0x6a09e667; s->h[1]=0xbb67ae85; s->h[2]=0x3c6ef372; s->h[3]=0xa54ff53a;
    s->h[4]=0x510e527f; s->h[5]=0x9b05688c; s->h[6]=0x1f83d9ab; s->h[7]=0x5be0cd19;
    s->total = 0; s->n = 0;
}

static void sha_update(sctx *s, const uchar *data, uint len)
{
    s->total += len;
    for (uint i = 0; i < len; i++) {
        s->buf[s->n++] = data[i];
        if (s->n == 64) { sha_compress(s->h, s->buf); s->n = 0; }
    }
}

static void sha_final(sctx *s, uchar out[32])
{
    ulong bits = (ulong)s->total * 8;
    uchar pad = 0x80;
    sha_update(s, &pad, 1);
    uchar z = 0;
    while (s->n != 56) sha_update(s, &z, 1);
    uchar len8[8];
    for (int i = 0; i < 8; i++) len8[i] = (uchar)(bits >> (56 - 8*i));
    sha_update(s, len8, 8);
    for (int i = 0; i < 8; i++) {
        out[4*i]   = (uchar)(s->h[i]>>24); out[4*i+1] = (uchar)(s->h[i]>>16);
        out[4*i+2] = (uchar)(s->h[i]>>8);  out[4*i+3] = (uchar)(s->h[i]);
    }
}

/* ---- PBKDF2-HMAC-SHA256, c=1, with pre-absorbed ipad/opad states -------- */

/* Build the ipad/opad SHA states for HMAC key = pw (private, len pwlen). */
static void hmac_states(sctx *istate, sctx *ostate, const uchar *pw, uint pwlen)
{
    uchar k[64];
    for (int i = 0; i < 64; i++) k[i] = 0;
    if (pwlen > 64) { sctx t; sha_init(&t); sha_update(&t, pw, pwlen); sha_final(&t, k); }
    else            for (uint i = 0; i < pwlen; i++) k[i] = pw[i];
    uchar ip[64], op[64];
    for (int i = 0; i < 64; i++) { ip[i] = k[i]^0x36; op[i] = k[i]^0x5c; }
    sha_init(istate); sha_update(istate, ip, 64);
    sha_init(ostate); sha_update(ostate, op, 64);
}

/* PBKDF2-1: B = PBKDF2(pw, salt, 1, p*128*r), the ROMix input blocks. */
static void pbkdf2_first(sctx istate, sctx ostate, const uchar salt[4],
                         __global uchar *B)
{
    uint nblocks = (BLK * SP) / 32;
    for (uint i = 1; i <= nblocks; i++) {
        uchar msg[8] = { salt[0],salt[1],salt[2],salt[3],
                         (uchar)(i>>24),(uchar)(i>>16),(uchar)(i>>8),(uchar)i };
        sctx c = istate; sha_update(&c, msg, 8); uchar inner[32]; sha_final(&c, inner);
        sctx d = ostate; sha_update(&d, inner, 32); uchar T[32]; sha_final(&d, T);
        for (int k = 0; k < 32; k++) B[(i-1)*32 + k] = T[k];
    }
}

/* PBKDF2-2: out[0..63] = PBKDF2(pw, B, 1, 64), the final dh1||dh2. */
static void pbkdf2_final(sctx istate, sctx ostate, __global const uchar *B,
                         __global uchar *out64)
{
    for (uint i = 1; i <= 2; i++) {
        sctx c = istate;
        uchar chunk[64];
        uint total = BLK * SP;
        for (uint off = 0; off < total; off += 64) {
            for (int k = 0; k < 64; k++) chunk[k] = B[off + k];
            sha_update(&c, chunk, 64);
        }
        uchar ctr[4] = { (uchar)(i>>24),(uchar)(i>>16),(uchar)(i>>8),(uchar)i };
        sha_update(&c, ctr, 4);
        uchar inner[32]; sha_final(&c, inner);
        sctx d = ostate; sha_update(&d, inner, 32); uchar T[32]; sha_final(&d, T);
        for (int k = 0; k < 32; k++) out64[(i-1)*32 + k] = T[k];
    }
}

/* Little-endian 32-bit load/store over a global byte buffer. */
static uint ld32le(__global const uchar *p)
{ return p[0] | ((uint)p[1]<<8) | ((uint)p[2]<<16) | ((uint)p[3]<<24); }
static void st32le(__global uchar *p, uint v)
{ p[0]=(uchar)v; p[1]=(uchar)(v>>8); p[2]=(uchar)(v>>16); p[3]=(uchar)(v>>24); }

/* ---- Salsa20/8 + BlockMix + ROMix -------------------------------------- */

#define R32(a,b) rotate((uint)(a), (uint)(b))

static void salsa20_8_le(__global uchar *blk)   /* in place on 64 bytes */
{
    uint x[16], in[16];
    for (int i = 0; i < 16; i++) in[i] = x[i] = ld32le(blk + 4*i);
    for (int i = 0; i < 8; i += 2) {
        x[ 4]^=R32(x[ 0]+x[12], 7); x[ 8]^=R32(x[ 4]+x[ 0], 9);
        x[12]^=R32(x[ 8]+x[ 4],13); x[ 0]^=R32(x[12]+x[ 8],18);
        x[ 9]^=R32(x[ 5]+x[ 1], 7); x[13]^=R32(x[ 9]+x[ 5], 9);
        x[ 1]^=R32(x[13]+x[ 9],13); x[ 5]^=R32(x[ 1]+x[13],18);
        x[14]^=R32(x[10]+x[ 6], 7); x[ 2]^=R32(x[14]+x[10], 9);
        x[ 6]^=R32(x[ 2]+x[14],13); x[10]^=R32(x[ 6]+x[ 2],18);
        x[ 3]^=R32(x[15]+x[11], 7); x[ 7]^=R32(x[ 3]+x[15], 9);
        x[11]^=R32(x[ 7]+x[ 3],13); x[15]^=R32(x[11]+x[ 7],18);
        x[ 1]^=R32(x[ 0]+x[ 3], 7); x[ 2]^=R32(x[ 1]+x[ 0], 9);
        x[ 3]^=R32(x[ 2]+x[ 1],13); x[ 0]^=R32(x[ 3]+x[ 2],18);
        x[ 6]^=R32(x[ 5]+x[ 4], 7); x[ 7]^=R32(x[ 6]+x[ 5], 9);
        x[ 4]^=R32(x[ 7]+x[ 6],13); x[ 5]^=R32(x[ 4]+x[ 7],18);
        x[11]^=R32(x[10]+x[ 9], 7); x[ 8]^=R32(x[11]+x[10], 9);
        x[ 9]^=R32(x[ 8]+x[11],13); x[10]^=R32(x[ 9]+x[ 8],18);
        x[12]^=R32(x[15]+x[14], 7); x[13]^=R32(x[12]+x[15], 9);
        x[14]^=R32(x[13]+x[12],13); x[15]^=R32(x[14]+x[13],18);
    }
    for (int i = 0; i < 16; i++) st32le(blk + 4*i, x[i] + in[i]);
}

/* BlockMix on 2r 64-byte sub-blocks of B (BLK bytes), scratch Y (BLK bytes). */
static void blockmix(__global uchar *B, __global uchar *Y)
{
    uchar X[64];
    for (int i = 0; i < 64; i++) X[i] = B[(2*SR-1)*64 + i];
    for (uint i = 0; i < 2*SR; i++) {
        for (int k = 0; k < 64; k++) X[k] ^= B[i*64 + k];
        /* salsa on the private X: reuse the LE core via a tiny global staging
         * is avoided -- do it in place on X with a private variant */
        uint x[16], in[16];
        for (int k = 0; k < 16; k++)
            in[k] = x[k] = X[4*k] | ((uint)X[4*k+1]<<8) | ((uint)X[4*k+2]<<16) | ((uint)X[4*k+3]<<24);
        for (int r = 0; r < 8; r += 2) {
            x[ 4]^=R32(x[ 0]+x[12], 7); x[ 8]^=R32(x[ 4]+x[ 0], 9);
            x[12]^=R32(x[ 8]+x[ 4],13); x[ 0]^=R32(x[12]+x[ 8],18);
            x[ 9]^=R32(x[ 5]+x[ 1], 7); x[13]^=R32(x[ 9]+x[ 5], 9);
            x[ 1]^=R32(x[13]+x[ 9],13); x[ 5]^=R32(x[ 1]+x[13],18);
            x[14]^=R32(x[10]+x[ 6], 7); x[ 2]^=R32(x[14]+x[10], 9);
            x[ 6]^=R32(x[ 2]+x[14],13); x[10]^=R32(x[ 6]+x[ 2],18);
            x[ 3]^=R32(x[15]+x[11], 7); x[ 7]^=R32(x[ 3]+x[15], 9);
            x[11]^=R32(x[ 7]+x[ 3],13); x[15]^=R32(x[11]+x[ 7],18);
            x[ 1]^=R32(x[ 0]+x[ 3], 7); x[ 2]^=R32(x[ 1]+x[ 0], 9);
            x[ 3]^=R32(x[ 2]+x[ 1],13); x[ 0]^=R32(x[ 3]+x[ 2],18);
            x[ 6]^=R32(x[ 5]+x[ 4], 7); x[ 7]^=R32(x[ 6]+x[ 5], 9);
            x[ 4]^=R32(x[ 7]+x[ 6],13); x[ 5]^=R32(x[ 4]+x[ 7],18);
            x[11]^=R32(x[10]+x[ 9], 7); x[ 8]^=R32(x[11]+x[10], 9);
            x[ 9]^=R32(x[ 8]+x[11],13); x[10]^=R32(x[ 9]+x[ 8],18);
            x[12]^=R32(x[15]+x[14], 7); x[13]^=R32(x[12]+x[15], 9);
            x[14]^=R32(x[13]+x[12],13); x[15]^=R32(x[14]+x[13],18);
        }
        for (int k = 0; k < 16; k++) {
            uint v = x[k] + in[k];
            X[4*k]=(uchar)v; X[4*k+1]=(uchar)(v>>8); X[4*k+2]=(uchar)(v>>16); X[4*k+3]=(uchar)(v>>24);
        }
        for (int k = 0; k < 64; k++) Y[i*64 + k] = X[k];
    }
    /* regroup even sub-blocks then odd sub-blocks back into B (byte-wise, so B
     * is only ever viewed as uchar -- no strict-aliasing hazard with salsa's
     * uchar reads above) */
    for (uint i = 0; i < SR; i++)
        for (int k = 0; k < 64; k++) B[i*64 + k] = Y[(2*i)*64 + k];
    for (uint i = 0; i < SR; i++)
        for (int k = 0; k < 64; k++) B[(SR+i)*64 + k] = Y[(2*i+1)*64 + k];
}

static void romix(__global uchar *B, __global uchar *V, __global uchar *Y, uint N)
{
    for (uint i = 0; i < N; i++) {
        __global uchar *Vi = V + (size_t)i*BLK;
        for (uint b = 0; b < BLK; b++) Vi[b] = B[b];
        blockmix(B, Y);
    }
    for (uint i = 0; i < N; i++) {
        uint j = ld32le(B + (2*SR-1)*64) & (N - 1);
        __global uchar *Vj = V + (size_t)j*BLK;
        for (uint b = 0; b < BLK; b++) B[b] ^= Vj[b];
        blockmix(B, Y);
    }
}

/* ---- the kernel -------------------------------------------------------- */

/* SN is the compile-time MAX N the V buffer is sized for (the per-lane stride);
 * the runtime arg N (a power of two, N <= SN) is the actual iteration count, so
 * the same build can run a small N under a display watchdog and the full N on
 * a headless card. */
__kernel void scrypt_kdf(
    __global const uchar *pw,       /* MAXPW * nlanes */
    __global const uint  *pwlen,    /* nlanes */
    const uint            saltw,    /* 4 salt bytes packed s0|s1<<8|s2<<16|s3<<24 */
    __global uchar       *out,      /* 64 * nlanes */
    __global uchar       *gV,       /* BLK*SN * nlanes */
    __global uchar       *gB,       /* BLK*SP * nlanes */
    __global uchar       *gY,       /* BLK    * nlanes */
    const uint            N)        /* runtime iteration count, N <= SN */
{
    uint gid = get_global_id(0);

    /* copy this lane's passphrase into private memory (HMAC key) */
    uchar mypw[MAXPW];
    uint  mylen = pwlen[gid];
    if (mylen > MAXPW) mylen = MAXPW;
    for (uint i = 0; i < mylen; i++) mypw[i] = pw[(size_t)gid*MAXPW + i];

    sctx istate, ostate;
    hmac_states(&istate, &ostate, mypw, mylen);

    __global uchar *B = gB + (size_t)gid * BLK * SP;
    __global uchar *V = gV + (size_t)gid * BLK * SN;
    __global uchar *Y = gY + (size_t)gid * BLK;

    /* B = PBKDF2(pw, salt, 1, p*128*r) -- salt is the 4-byte addrhash */
    uchar salt[4] = { (uchar)saltw, (uchar)(saltw>>8), (uchar)(saltw>>16), (uchar)(saltw>>24) };
    pbkdf2_first(istate, ostate, salt, B);

#ifdef DBG
    if (DBG == 1) {   /* dump the first 64 bytes of B after PBKDF2-1 */
        for (int k = 0; k < 64; k++) out[(size_t)gid*64 + k] = B[k];
        return;
    }
#endif

#ifdef DBG
    if (DBG == 3) {   /* one blockmix on block 0, then dump 64 bytes */
        blockmix(B, Y);
        for (int k = 0; k < 64; k++) out[(size_t)gid*64 + k] = B[k];
        return;
    }
    if (DBG == 4) {   /* ROMix fill loop only (N blockmixes), then dump */
        __global uint *Bv = (__global uint *)B;
        for (uint i = 0; i < N; i++) {
            __global uint *Vi = (__global uint *)(V + (size_t)i*BLK);
            for (uint k = 0; k < BWORDS; k++) Vi[k] = Bv[k];
            blockmix(B, Y);
        }
        for (int k = 0; k < 64; k++) out[(size_t)gid*64 + k] = B[k];
        return;
    }
#endif

    /* p independent ROMix passes over the p blocks of B */
    for (uint i = 0; i < SP; i++)
        romix(B + (size_t)i*BLK, V, Y, N);

#ifdef DBG
    if (DBG == 2) {   /* dump the first 64 bytes of B after ROMix */
        for (int k = 0; k < 64; k++) out[(size_t)gid*64 + k] = B[k];
        return;
    }
#endif

    /* out = PBKDF2(pw, B, 1, 64) */
    pbkdf2_final(istate, ostate, B, out + (size_t)gid * 64);
}

/* ---- phased kernel: watchdog-safe scrypt across many short launches ------ *
 * The host drives one candidate batch through: phase 0 (PBKDF2-1 -> gB), then
 * per ROMix pass a run of phase-1 (fill) and phase-2 (mix) chunks over
 * [iStart,iEnd), then phase 3 (PBKDF2-2 -> out). State persists in gB/gV
 * between launches, so each launch does a bounded slice of work and never
 * runs long enough to trip a GPU watchdog. */
__kernel void scrypt_phase(
    __global const uchar *pw, __global const uint *pwlen, const uint saltw,
    __global uchar *out, __global uchar *gV, __global uchar *gB, __global uchar *gY,
    const uint phase, const uint N, const uint passIdx,
    const uint iStart, const uint iEnd)
{
    uint gid = get_global_id(0);
    __global uchar *B  = gB + (size_t)gid * BLK * SP + (size_t)passIdx * BLK;
    __global uchar *V  = gV + (size_t)gid * BLK * SN;
    __global uchar *Y  = gY + (size_t)gid * BLK;

    if (phase == 1) {                    /* ROMix fill chunk */
        for (uint i = iStart; i < iEnd; i++) {
            __global uchar *Vi = V + (size_t)i*BLK;
            for (uint b = 0; b < BLK; b++) Vi[b] = B[b];
            blockmix(B, Y);
        }
        return;
    }
    if (phase == 2) {                    /* ROMix mix chunk */
        for (uint i = iStart; i < iEnd; i++) {
            uint j = ld32le(B + (2*SR-1)*64) & (N - 1);
            __global uchar *Vj = V + (size_t)j*BLK;
            for (uint b = 0; b < BLK; b++) B[b] ^= Vj[b];
            blockmix(B, Y);
        }
        return;
    }

    /* phases 0 and 3 need the passphrase (HMAC key) */
    uchar mypw[MAXPW];
    uint mylen = pwlen[gid];
    if (mylen > MAXPW) mylen = MAXPW;
    for (uint i = 0; i < mylen; i++) mypw[i] = pw[(size_t)gid*MAXPW + i];
    sctx istate, ostate;
    hmac_states(&istate, &ostate, mypw, mylen);

    __global uchar *Bbase = gB + (size_t)gid * BLK * SP;
    if (phase == 0) {
        uchar salt[4] = { (uchar)saltw, (uchar)(saltw>>8), (uchar)(saltw>>16), (uchar)(saltw>>24) };
        pbkdf2_first(istate, ostate, salt, Bbase);
    } else {                             /* phase 3 */
        pbkdf2_final(istate, ostate, Bbase, out + (size_t)gid * 64);
    }
}
