/*
 * scrypt.cl -- the scrypt(N,r,p) kernel for rxe38's GPU backend.
 *
 * One work-item = one candidate passphrase. Each lane computes the full
 * scrypt KDF and writes the 64-byte dh1||dh2 the host needs; the host then
 * finishes AES + secp256k1 + address-verify. scrypt is ~99.99% of the per-
 * candidate cost, so this offloads essentially all of it.
 *
 * MEMORY LAYOUT -- coalesced, lane-interleaved. The block/scratchpad words are
 * stored word-major with the LANE as the innermost (fastest-varying) index:
 * word w of a lane's buffer lives at [w * NLANES + gid]. So the 32 lanes of a
 * warp reading "word w" hit 32 consecutive addresses = one coalesced memory
 * transaction, instead of 32 scattered ones 16 MB apart (the lane-major layout
 * wastes ~all of the card's bandwidth on this memory-hard kernel). Words are
 * stored as their little-endian scrypt values, so Salsa20/8 reads them straight
 * into registers -- no per-access byte shuffling. Validated byte-exact vs the
 * CPU reference in rxe38.c (--gpu-scrypt-test / --gpu-phase-test).
 *
 * Compile-time: -D SN=<maxN> -D SR=<r> -D SP=<p> -D MAXPW=<max pw bytes>.
 * SN sizes the V scratchpad (per-lane stride); the runtime N (<= SN) is the
 * actual iteration count. NLANES is a runtime kernel arg (the batch size).
 *
 *          (C) 2026 Marco "Kiko" Carnut <kiko at postcogito dot org>, GPLv2.
 */

#define BLK    (128u * SR)       /* bytes in one scrypt block (1024 for r=8) */
#define BWORDS (32u * SR)        /* uint words in one block (256 for r=8)     */
#define BWORDS4 (8u * SR)        /* uint4 quartets in one block (64 for r=8)  */
#define YO4     (4u * SR)        /* uint4 for BlockMix's odd-output scratch    */

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

/* ---- PBKDF2-1/-2, coalesced word layout -------------------------------- *
 * gB holds P*BWORDS words per lane, flat word index wp at [wp*NL + gid]. */

/* B = PBKDF2(pw, salt, 1, p*128*r), stored as little-endian words. */
static void pbkdf2_first(sctx istate, sctx ostate, const uchar salt[4],
                         __global uint *gB, uint NL, uint gid)
{
    uint nblocks = (BLK * SP) / 32;                     /* 32-byte HMAC blocks */
    for (uint i = 1; i <= nblocks; i++) {
        uchar msg[8] = { salt[0],salt[1],salt[2],salt[3],
                         (uchar)(i>>24),(uchar)(i>>16),(uchar)(i>>8),(uchar)i };
        sctx c = istate; sha_update(&c, msg, 8); uchar inner[32]; sha_final(&c, inner);
        sctx d = ostate; sha_update(&d, inner, 32); uchar T[32]; sha_final(&d, T);
        for (int k = 0; k < 8; k++) {
            uint wp = (i-1)*8 + k;
            gB[wp*NL + gid] = (uint)T[4*k] | ((uint)T[4*k+1]<<8)
                            | ((uint)T[4*k+2]<<16) | ((uint)T[4*k+3]<<24);
        }
    }
}

/* out[0..63] = PBKDF2(pw, B, 1, 64), reading B's words back as a byte stream. */
static void pbkdf2_final(sctx istate, sctx ostate, __global const uint *gB,
                         __global uchar *out64, uint NL, uint gid)
{
    for (uint i = 1; i <= 2; i++) {
        sctx c = istate;
        uint totalw = BWORDS * SP;                      /* words in the p blocks */
        for (uint off = 0; off < totalw; off += 16) {   /* 16 words = 64 bytes */
            uchar chunk[64];
            for (int m = 0; m < 16; m++) {
                uint v = gB[(off + m)*NL + gid];
                chunk[4*m]=(uchar)v; chunk[4*m+1]=(uchar)(v>>8);
                chunk[4*m+2]=(uchar)(v>>16); chunk[4*m+3]=(uchar)(v>>24);
            }
            sha_update(&c, chunk, 64);
        }
        uchar ctr[4] = { (uchar)(i>>24),(uchar)(i>>16),(uchar)(i>>8),(uchar)i };
        sha_update(&c, ctr, 4);
        uchar inner[32]; sha_final(&c, inner);
        sctx d = ostate; sha_update(&d, inner, 32); uchar T[32]; sha_final(&d, T);
        for (int k = 0; k < 32; k++) out64[(i-1)*32 + k] = T[k];
    }
}

/* ---- Salsa20/8 + BlockMix + ROMix (uint words, coalesced) -------------- */

#define R32(a,b) rotate((uint)(a), (uint)(b))

static void salsa20_8(uint B[16])
{
    uint x[16];
    for (int i = 0; i < 16; i++) x[i] = B[i];
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
    for (int i = 0; i < 16; i++) B[i] += x[i];
}

/* ---- private (L1-backed), uint4-vectorized working-block variants ------- *
 *
 * The old __global blockmix/romix round-tripped the 256-word working block and
 * the Y scratch through __global on every BlockMix -- most of that is NOT the
 * fundamental V traffic, it lengthens each lane's dependent chain, and it is why
 * we stalled at ~4-16% of memory bandwidth.
 *
 * These variants keep the block, the Y scratch and the TMTO walk block in
 * PRIVATE arrays (per-thread "local memory", L1/L2-backed -- NOT the 48 KB
 * __shared__ pool, which one warp's blocks would blow) for the whole ROMix
 * pass, so BlockMix/Salsa/the walk run at cache speed. They are stored as
 * `uint4` quartets: the block's dominant traffic is the private load/store of
 * b/y in BlockMix, so 128-bit accesses cut the LSU/local-memory transaction
 * count ~4x, and the V fill/read is one coalesced uint4 per quartet. __global
 * is touched only for the fundamental V fill-writes/mix-reads (lane-interleaved
 * uint4) plus one load/store of the pass block at the PBKDF2 (uint) boundary.
 * Byte-identical results; validated via --gpu-scrypt-test / --gpu-phase-test. */
/* BlockMix without a full Y scratch. Output B' = (Y0,Y2,..,Y2r-2, Y1,Y3,..).
 * The X chain carries Y_{i-1} in registers, so Y is needed only to reorder: the
 * EVEN outputs Y_{2m} land in the low half at sub-block m = i/2 <= i, a slot
 * already consumed, so we write them straight into b in place; only the ODD
 * outputs (high half) would clobber a not-yet-read sub-block, so just those are
 * buffered (r sub-blocks = half the old Y) and copied up at the end. Cuts the
 * per-BlockMix local traffic ~25% (1024 -> 768 word-accesses). yo has YO4 uint4. */
static void blockmix_p(uint4 *b, uint4 *yo)
{
    uint X[16];
    {
        uint4 q0=b[4*(2*SR-1)], q1=b[4*(2*SR-1)+1], q2=b[4*(2*SR-1)+2], q3=b[4*(2*SR-1)+3];
        X[0]=q0.x;X[1]=q0.y;X[2]=q0.z;X[3]=q0.w; X[4]=q1.x;X[5]=q1.y;X[6]=q1.z;X[7]=q1.w;
        X[8]=q2.x;X[9]=q2.y;X[10]=q2.z;X[11]=q2.w; X[12]=q3.x;X[13]=q3.y;X[14]=q3.z;X[15]=q3.w;
    }
    for (uint i = 0; i < 2*SR; i++) {
        uint4 q0=b[4*i], q1=b[4*i+1], q2=b[4*i+2], q3=b[4*i+3];
        X[0]^=q0.x;X[1]^=q0.y;X[2]^=q0.z;X[3]^=q0.w; X[4]^=q1.x;X[5]^=q1.y;X[6]^=q1.z;X[7]^=q1.w;
        X[8]^=q2.x;X[9]^=q2.y;X[10]^=q2.z;X[11]^=q2.w; X[12]^=q3.x;X[13]^=q3.y;X[14]^=q3.z;X[15]^=q3.w;
        salsa20_8(X);
        uint4 o0=(uint4)(X[0],X[1],X[2],X[3]),   o1=(uint4)(X[4],X[5],X[6],X[7]),
              o2=(uint4)(X[8],X[9],X[10],X[11]), o3=(uint4)(X[12],X[13],X[14],X[15]);
        uint m = i >> 1;
        if ((i & 1) == 0) { b[4*m]=o0;  b[4*m+1]=o1;  b[4*m+2]=o2;  b[4*m+3]=o3;  }
        else              { yo[4*m]=o0; yo[4*m+1]=o1; yo[4*m+2]=o2; yo[4*m+3]=o3; }
    }
    for (uint m = 0; m < SR; m++) {           /* buffered odd outputs -> high half */
        b[4*(SR+m)]=yo[4*m]; b[4*(SR+m)+1]=yo[4*m+1];
        b[4*(SR+m)+2]=yo[4*m+2]; b[4*(SR+m)+3]=yo[4*m+3];
    }
}

static void romix_p(__global uint *gB, __global uint4 *gV,
                    uint pass, uint N, uint gap, uint NL, uint gid)
{
    uint pbase = pass * BWORDS;
    uint4 b[BWORDS4], yo[YO4], t[BWORDS4];
    for (uint q = 0; q < BWORDS4; q++)        /* load pass block (uint gB -> uint4) */
        b[q] = (uint4)(gB[(pbase+4*q  )*NL+gid], gB[(pbase+4*q+1)*NL+gid],
                       gB[(pbase+4*q+2)*NL+gid], gB[(pbase+4*q+3)*NL+gid]);
    for (uint i = 0; i < N; i++) {
        if (i % gap == 0) {
            uint s = i / gap;
            for (uint q = 0; q < BWORDS4; q++) gV[(s*BWORDS4 + q)*NL + gid] = b[q];
        }
        blockmix_p(b, yo);
    }
    for (uint i = 0; i < N; i++) {
        uint j = b[4*(2*SR-1)].x & (N - 1);
        uint s = j / gap, steps = j - s * gap;
        for (uint q = 0; q < BWORDS4; q++) t[q] = gV[(s*BWORDS4 + q)*NL + gid];
        for (uint st = 0; st < steps; st++) blockmix_p(t, yo);
        for (uint q = 0; q < BWORDS4; q++) b[q] ^= t[q];
        blockmix_p(b, yo);
    }
    for (uint q = 0; q < BWORDS4; q++) {      /* store pass block (uint4 -> uint gB) */
        gB[(pbase+4*q  )*NL+gid] = b[q].x; gB[(pbase+4*q+1)*NL+gid] = b[q].y;
        gB[(pbase+4*q+2)*NL+gid] = b[q].z; gB[(pbase+4*q+3)*NL+gid] = b[q].w;
    }
}

/* ---- monolithic kernel (validation / no-watchdog cards) ---------------- */

__kernel void scrypt_kdf(
    __global const uchar *pw, __global const uint *pwlen, const uint saltw,
    __global uchar *out, __global uint4 *gV, __global uint *gB, __global uint *gY,
    __global uint *gT, const uint N, const uint gap, const uint NL)
{
    uint gid = get_global_id(0);
    if (gid >= NL) return;

    uchar mypw[MAXPW];
    uint mylen = pwlen[gid];
    if (mylen > MAXPW) mylen = MAXPW;
    for (uint i = 0; i < mylen; i++) mypw[i] = pw[(size_t)gid*MAXPW + i];
    sctx istate, ostate;
    hmac_states(&istate, &ostate, mypw, mylen);

    uchar salt[4] = { (uchar)saltw, (uchar)(saltw>>8), (uchar)(saltw>>16), (uchar)(saltw>>24) };
    pbkdf2_first(istate, ostate, salt, gB, NL, gid);
    for (uint pass = 0; pass < SP; pass++)
        romix_p(gB, gV, pass, N, gap, NL, gid);   /* private (L1) working block */
    pbkdf2_final(istate, ostate, gB, out + (size_t)gid * 64, NL, gid);
    (void)gY; (void)gT;                            /* unused by the private path */
}

/* ---- phased kernel: watchdog-safe scrypt across many short launches ----- */

__kernel void scrypt_phase(
    __global const uchar *pw, __global const uint *pwlen, const uint saltw,
    __global uchar *out, __global uint4 *gV, __global uint *gB, __global uint *gY,
    __global uint *gT, const uint phase, const uint N, const uint gap,
    const uint passIdx, const uint iStart, const uint iEnd, const uint NL)
{
    uint gid = get_global_id(0);
    if (gid >= NL) return;
    uint pbase = passIdx * BWORDS;

    /* Same TMTO lookup-gap as romix_p(), but each fill/mix chunk covers only
     * [iStart,iEnd) so a launch stays short (watchdog-safe). The working block
     * is loaded into a PRIVATE (L1-backed) array for the chunk and stored back
     * at the end -- the load/store amortizes over the chunk, and BlockMix/Salsa/
     * the recompute walk run at cache speed instead of round-tripping __global
     * (the whole point of this pass). The walk is self-contained within one mix
     * iteration, so chunking needs no cross-launch state. gap==1 == plain ROMix. */
    if (phase == 1) {                    /* ROMix fill chunk (store every gap-th) */
        uint4 b[BWORDS4], yo[YO4];
        for (uint q = 0; q < BWORDS4; q++)
            b[q] = (uint4)(gB[(pbase+4*q  )*NL+gid], gB[(pbase+4*q+1)*NL+gid],
                           gB[(pbase+4*q+2)*NL+gid], gB[(pbase+4*q+3)*NL+gid]);
        for (uint i = iStart; i < iEnd; i++) {
            if (i % gap == 0) {
                uint s = i / gap;
                for (uint q = 0; q < BWORDS4; q++) gV[(s*BWORDS4 + q)*NL + gid] = b[q];
            }
            blockmix_p(b, yo);
        }
        for (uint q = 0; q < BWORDS4; q++) {
            gB[(pbase+4*q  )*NL+gid] = b[q].x; gB[(pbase+4*q+1)*NL+gid] = b[q].y;
            gB[(pbase+4*q+2)*NL+gid] = b[q].z; gB[(pbase+4*q+3)*NL+gid] = b[q].w;
        }
        return;
    }
    if (phase == 2) {                    /* ROMix mix chunk (recompute misses) */
        uint4 b[BWORDS4], yo[YO4], t[BWORDS4];
        for (uint q = 0; q < BWORDS4; q++)
            b[q] = (uint4)(gB[(pbase+4*q  )*NL+gid], gB[(pbase+4*q+1)*NL+gid],
                           gB[(pbase+4*q+2)*NL+gid], gB[(pbase+4*q+3)*NL+gid]);
        for (uint i = iStart; i < iEnd; i++) {
            uint j = b[4*(2*SR-1)].x & (N - 1);
            uint s = j / gap, steps = j - s * gap;
            for (uint q = 0; q < BWORDS4; q++) t[q] = gV[(s*BWORDS4 + q)*NL + gid];
            for (uint st = 0; st < steps; st++) blockmix_p(t, yo);
            for (uint q = 0; q < BWORDS4; q++) b[q] ^= t[q];
            blockmix_p(b, yo);
        }
        for (uint q = 0; q < BWORDS4; q++) {
            gB[(pbase+4*q  )*NL+gid] = b[q].x; gB[(pbase+4*q+1)*NL+gid] = b[q].y;
            gB[(pbase+4*q+2)*NL+gid] = b[q].z; gB[(pbase+4*q+3)*NL+gid] = b[q].w;
        }
        return;
    }

    uchar mypw[MAXPW];
    uint mylen = pwlen[gid];
    if (mylen > MAXPW) mylen = MAXPW;
    for (uint i = 0; i < mylen; i++) mypw[i] = pw[(size_t)gid*MAXPW + i];
    sctx istate, ostate;
    hmac_states(&istate, &ostate, mypw, mylen);

    if (phase == 0) {
        uchar salt[4] = { (uchar)saltw, (uchar)(saltw>>8), (uchar)(saltw>>16), (uchar)(saltw>>24) };
        pbkdf2_first(istate, ostate, salt, gB, NL, gid);
    } else {                             /* phase 3 */
        pbkdf2_final(istate, ostate, gB, out + (size_t)gid * 64, NL, gid);
    }
}

/* ==================================================================== *
 * WARP-COOPERATIVE ROMix prototype (T=4 threads/candidate, gap=1).
 *
 * 4 consecutive work-items form one candidate-group; thread lt(0..3) owns
 * block words {4q+lt : q=0..COOPW-1}. Salsa20/8 uses the 4x4 thread=column
 * mapping: columnrounds are thread-local, rowrounds transpose through __local
 * (NVIDIA OpenCL exposes no subgroup shuffle, so __local+barrier is the only
 * cross-lane path). WG MUST be 32 (8 groups); NLC (candidate count) MUST be a
 * multiple of 8 so every work-group is uniformly active (no barrier divergence).
 * No TMTO (gap=1): all groups run identical BlockMix counts, so every barrier
 * is reached by all 32 threads. Byte-exact vs the scalar romix (CPU-modelled
 * first in /tmp/coop_romix.c, gated here by --coop-test vs rxe38.c's romix).
 * ==================================================================== */
#define COOPW (BWORDS/4u)          /* words each of the 4 threads owns (64) */

static inline void cqr(uint w[4], uint st)          /* quarterround, cyclic start st */
{
    uint a=w[st&3u], b=w[(st+1u)&3u], c=w[(st+2u)&3u], d=w[(st+3u)&3u];
    b ^= R32(a+d,7); c ^= R32(b+a,9); d ^= R32(c+b,13); a ^= R32(d+c,18);
    w[st&3u]=a; w[(st+1u)&3u]=b; w[(st+2u)&3u]=c; w[(st+3u)&3u]=d;
}

/* cooperative salsa20/8 on Xc (thread lt holds column lt = 4 words). Salsa20 is
 * out = in + core(in) -- the final feedforward add is element-wise, so it stays
 * thread-local (no exchange). Omitting it is a silent bug that still matches any
 * other feedforward-less model; only the oracle-gated scalar romix catches it. */
static inline void salsa_coop(uint Xc[4], __local uint *xg, uint lg, uint lt)
{
    uint base = lg*16u, in0=Xc[0], in1=Xc[1], in2=Xc[2], in3=Xc[3];
    for (int dr = 0; dr < 4; dr++) {
        cqr(Xc, lt);                                          /* column round  */
        barrier(CLK_LOCAL_MEM_FENCE);
        for (int r = 0; r < 4; r++) xg[base + r*4 + lt] = Xc[r];   /* -> local  */
        barrier(CLK_LOCAL_MEM_FENCE);
        uint row[4];
        for (int c = 0; c < 4; c++) row[c] = xg[base + lt*4 + c];  /* my row    */
        cqr(row, lt);                                         /* row round     */
        barrier(CLK_LOCAL_MEM_FENCE);
        for (int c = 0; c < 4; c++) xg[base + lt*4 + c] = row[c];  /* -> local  */
        barrier(CLK_LOCAL_MEM_FENCE);
        for (int r = 0; r < 4; r++) Xc[r] = xg[base + r*4 + lt];   /* my column */
    }
    Xc[0]+=in0; Xc[1]+=in1; Xc[2]+=in2; Xc[3]+=in3;      /* Salsa20 feedforward */
}

static inline void blockmix_coop(uint *bl, __local uint *xg, uint lg, uint lt)
{
    uint Xc[4], Yc[COOPW];
    for (int r = 0; r < 4; r++) Xc[r] = bl[(2*SR-1)*4 + r];        /* subblock 2r-1 */
    for (uint i = 0; i < 2*SR; i++) {
        for (int r = 0; r < 4; r++) Xc[r] ^= bl[i*4 + r];
        salsa_coop(Xc, xg, lg, lt);
        for (int r = 0; r < 4; r++) Yc[i*4 + r] = Xc[r];
    }
    for (uint m = 0; m < SR; m++) for (int r=0;r<4;r++) bl[m*4 + r]      = Yc[(2*m)*4 + r];
    for (uint m = 0; m < SR; m++) for (int r=0;r<4;r++) bl[(SR+m)*4 + r] = Yc[(2*m+1)*4 + r];
}

/* ONE ROMix pass per launch (the host loops passes 0..PP-1). An in-kernel pass
 * loop wrapping the barrier-containing ROMix miscompiles on NVIDIA's ptxas
 * (barrier reconvergence in a nested loop corrupts __local for every group
 * except base 0) -- verified in isolation. One pass/launch sidesteps it, mirrors
 * the phased kernel, and needs no cross-launch state (passes are independent). */
__kernel void scrypt_romix_coop(
    __global const uint *gIn, __global uint *gV, __global uint *gOut,
    const uint N, const uint NLC, const uint PP, const uint pass)
{
    __local uint xg[8*16];                        /* 8 groups * 16 words       */
    uint gid = get_global_id(0), cand = gid>>2, lt = gid&3u, lg = get_local_id(0)>>2;
    /* NO early-return guard: a conditional return before the mix-loop barriers
     * is control flow the compiler cannot prove uniform, and it miscompiles the
     * barrier reconvergence (silent per-group corruption) even when no thread
     * actually returns. The host guarantees global == NLC*4 with NLC%8==0, so
     * every work-item is a valid candidate lane -- no guard is needed. */
    (void)NLC;
    uint bl[COOPW];
    size_t vbase = (size_t)cand * N * BWORDS;
    size_t ibase = ((size_t)cand*PP + pass) * BWORDS;
    for (uint q = 0; q < COOPW; q++) bl[q] = gIn[ibase + 4*q + lt];
    for (uint i = 0; i < N; i++) {                            /* ROMix fill    */
        size_t vb = vbase + (size_t)i*BWORDS;
        for (uint q = 0; q < COOPW; q++) gV[vb + 4*q + lt] = bl[q];
        blockmix_coop(bl, xg, lg, lt);
    }
    for (uint i = 0; i < N; i++) {                            /* ROMix mix     */
        barrier(CLK_LOCAL_MEM_FENCE);
        if (lt == 0) xg[lg*16u] = bl[(2*SR-1)*4];             /* word 240 -> j  */
        barrier(CLK_LOCAL_MEM_FENCE);
        uint j = xg[lg*16u] & (N-1u);
        barrier(CLK_LOCAL_MEM_FENCE);
        size_t vb = vbase + (size_t)j*BWORDS;
        for (uint q = 0; q < COOPW; q++) bl[q] ^= gV[vb + 4*q + lt];
        blockmix_coop(bl, xg, lg, lt);
    }
    for (uint q = 0; q < COOPW; q++) gOut[ibase + 4*q + lt] = bl[q];
}
