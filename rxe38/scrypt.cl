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

/* BlockMix on pass `pass`'s block (2r sub-blocks of 16 words), scratch gY. */
static void blockmix(__global uint *gB, __global uint *gY,
                     uint pass, uint NL, uint gid)
{
    uint pbase = pass * BWORDS;
    uint X[16];
    for (int k = 0; k < 16; k++) X[k] = gB[(pbase + (2*SR-1)*16 + k)*NL + gid];
    for (uint i = 0; i < 2*SR; i++) {
        for (int k = 0; k < 16; k++) X[k] ^= gB[(pbase + i*16 + k)*NL + gid];
        salsa20_8(X);
        for (int k = 0; k < 16; k++) gY[(i*16 + k)*NL + gid] = X[k];
    }
    for (uint i = 0; i < SR; i++)
        for (int k = 0; k < 16; k++)
            gB[(pbase + i*16 + k)*NL + gid] = gY[((2*i)*16 + k)*NL + gid];
    for (uint i = 0; i < SR; i++)
        for (int k = 0; k < 16; k++)
            gB[(pbase + (SR+i)*16 + k)*NL + gid] = gY[((2*i+1)*16 + k)*NL + gid];
}

/* ROMix pass `pass` in place (used by the monolithic kernel). */
static void romix(__global uint *gB, __global uint *gV, __global uint *gY,
                  uint pass, uint N, uint NL, uint gid)
{
    uint pbase = pass * BWORDS;
    for (uint i = 0; i < N; i++) {
        for (uint w = 0; w < BWORDS; w++)
            gV[(i*BWORDS + w)*NL + gid] = gB[(pbase + w)*NL + gid];
        blockmix(gB, gY, pass, NL, gid);
    }
    for (uint i = 0; i < N; i++) {
        uint j = gB[(pbase + (2*SR-1)*16)*NL + gid] & (N - 1);
        for (uint w = 0; w < BWORDS; w++)
            gB[(pbase + w)*NL + gid] ^= gV[(j*BWORDS + w)*NL + gid];
        blockmix(gB, gY, pass, NL, gid);
    }
}

/* ---- monolithic kernel (validation / no-watchdog cards) ---------------- */

__kernel void scrypt_kdf(
    __global const uchar *pw, __global const uint *pwlen, const uint saltw,
    __global uchar *out, __global uint *gV, __global uint *gB, __global uint *gY,
    const uint N, const uint NL)
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
        romix(gB, gV, gY, pass, N, NL, gid);
    pbkdf2_final(istate, ostate, gB, out + (size_t)gid * 64, NL, gid);
}

/* ---- phased kernel: watchdog-safe scrypt across many short launches ----- */

__kernel void scrypt_phase(
    __global const uchar *pw, __global const uint *pwlen, const uint saltw,
    __global uchar *out, __global uint *gV, __global uint *gB, __global uint *gY,
    const uint phase, const uint N, const uint passIdx,
    const uint iStart, const uint iEnd, const uint NL)
{
    uint gid = get_global_id(0);
    if (gid >= NL) return;
    uint pbase = passIdx * BWORDS;

    if (phase == 1) {                    /* ROMix fill chunk */
        for (uint i = iStart; i < iEnd; i++) {
            for (uint w = 0; w < BWORDS; w++)
                gV[(i*BWORDS + w)*NL + gid] = gB[(pbase + w)*NL + gid];
            blockmix(gB, gY, passIdx, NL, gid);
        }
        return;
    }
    if (phase == 2) {                    /* ROMix mix chunk */
        for (uint i = iStart; i < iEnd; i++) {
            uint j = gB[(pbase + (2*SR-1)*16)*NL + gid] & (N - 1);
            for (uint w = 0; w < BWORDS; w++)
                gB[(pbase + w)*NL + gid] ^= gV[(j*BWORDS + w)*NL + gid];
            blockmix(gB, gY, passIdx, NL, gid);
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
