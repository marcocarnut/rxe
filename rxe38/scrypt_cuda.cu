/* rxe38 CUDA backend #2 -- scrypt ROMix kernel (NVRTC-compiled at runtime).
 *
 * Romix ONLY (hybrid design): the host does PBKDF2/HMAC (pbkdf2_first -> B,
 * pbkdf2_final -> dk) and all AES/secp/verify; the GPU does just the ROMix
 * passes -- the ~99.99% hot loop. This is the standalone-romix structure that
 * lets nvrtc/ptxas produce ~22% better sm_120 code than NVIDIA's OpenCL JIT
 * (measured on the 5090D: OpenCL pure-romix ~917, CUDA ~1123 cand-equiv/s).
 *
 * Layout is IDENTICAL to the OpenCL scrypt_romix_only path so gB is byte-for-
 * byte shared: word w of pass p, candidate gid, lives at gB[(p*BWORDS+w)*NL+gid]
 * (lane-interleaved -> coalesced). V is uint4 lane-interleaved, reused across
 * the p passes. Byte-exact vs rxe38.c's oracle romix at N=512 and N=16384.
 *
 * Compile-time -D: SR (=r), plus N/gap/NL/PP passed as kernel args. Built for
 * compute_89 PTX; the Blackwell (sm_120) driver JITs it forward-compatibly. */

#define BWORDS  (32u * SR)          /* 256 uint words / block (r=8)   */
#define BWORDS4 (8u * SR)           /* 64 uint4 quartets / block      */
#define YO4     (4u * SR)           /* 32 uint4 for the no-Y scratch  */
#define R32(a,b) (((a) << (b)) | ((a) >> (32u - (b))))
typedef unsigned u32;

__device__ __forceinline__ void salsa20_8(u32 X[16])
{
    u32 x[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) x[i] = X[i];
    #pragma unroll
    for (int i = 0; i < 8; i += 2) {
        x[ 4]^=R32(x[ 0]+x[12], 7); x[ 8]^=R32(x[ 4]+x[ 0], 9); x[12]^=R32(x[ 8]+x[ 4],13); x[ 0]^=R32(x[12]+x[ 8],18);
        x[ 9]^=R32(x[ 5]+x[ 1], 7); x[13]^=R32(x[ 9]+x[ 5], 9); x[ 1]^=R32(x[13]+x[ 9],13); x[ 5]^=R32(x[ 1]+x[13],18);
        x[14]^=R32(x[10]+x[ 6], 7); x[ 2]^=R32(x[14]+x[10], 9); x[ 6]^=R32(x[ 2]+x[14],13); x[10]^=R32(x[ 6]+x[ 2],18);
        x[ 3]^=R32(x[15]+x[11], 7); x[ 7]^=R32(x[ 3]+x[15], 9); x[11]^=R32(x[ 7]+x[ 3],13); x[15]^=R32(x[11]+x[ 7],18);
        x[ 1]^=R32(x[ 0]+x[ 3], 7); x[ 2]^=R32(x[ 1]+x[ 0], 9); x[ 3]^=R32(x[ 2]+x[ 1],13); x[ 0]^=R32(x[ 3]+x[ 2],18);
        x[ 6]^=R32(x[ 5]+x[ 4], 7); x[ 7]^=R32(x[ 6]+x[ 5], 9); x[ 4]^=R32(x[ 7]+x[ 6],13); x[ 5]^=R32(x[ 4]+x[ 7],18);
        x[11]^=R32(x[10]+x[ 9], 7); x[ 8]^=R32(x[11]+x[10], 9); x[ 9]^=R32(x[ 8]+x[11],13); x[10]^=R32(x[ 9]+x[ 8],18);
        x[12]^=R32(x[15]+x[14], 7); x[13]^=R32(x[12]+x[15], 9); x[14]^=R32(x[13]+x[12],13); x[15]^=R32(x[14]+x[13],18);
    }
    #pragma unroll
    for (int i = 0; i < 16; i++) X[i] += x[i];
}

/* No-Y BlockMix on a uint4 block b[BWORDS4], scratch yo[YO4] (even outputs in
 * place, odd outputs buffered) -- identical to the OpenCL blockmix_p. */
__device__ __forceinline__ void blockmix_p(uint4 *b, uint4 *yo)
{
    u32 X[16];
    {
        uint4 q0=b[4*(2*SR-1)], q1=b[4*(2*SR-1)+1], q2=b[4*(2*SR-1)+2], q3=b[4*(2*SR-1)+3];
        X[0]=q0.x;X[1]=q0.y;X[2]=q0.z;X[3]=q0.w; X[4]=q1.x;X[5]=q1.y;X[6]=q1.z;X[7]=q1.w;
        X[8]=q2.x;X[9]=q2.y;X[10]=q2.z;X[11]=q2.w; X[12]=q3.x;X[13]=q3.y;X[14]=q3.z;X[15]=q3.w;
    }
    #pragma unroll 1
    for (u32 i = 0; i < 2*SR; i++) {
        uint4 q0=b[4*i], q1=b[4*i+1], q2=b[4*i+2], q3=b[4*i+3];
        X[0]^=q0.x;X[1]^=q0.y;X[2]^=q0.z;X[3]^=q0.w; X[4]^=q1.x;X[5]^=q1.y;X[6]^=q1.z;X[7]^=q1.w;
        X[8]^=q2.x;X[9]^=q2.y;X[10]^=q2.z;X[11]^=q2.w; X[12]^=q3.x;X[13]^=q3.y;X[14]^=q3.z;X[15]^=q3.w;
        salsa20_8(X);
        uint4 o0=make_uint4(X[0],X[1],X[2],X[3]),   o1=make_uint4(X[4],X[5],X[6],X[7]),
              o2=make_uint4(X[8],X[9],X[10],X[11]), o3=make_uint4(X[12],X[13],X[14],X[15]);
        u32 m = i >> 1;
        if ((i & 1) == 0) { b[4*m]=o0;  b[4*m+1]=o1;  b[4*m+2]=o2;  b[4*m+3]=o3;  }
        else              { yo[4*m]=o0; yo[4*m+1]=o1; yo[4*m+2]=o2; yo[4*m+3]=o3; }
    }
    #pragma unroll 1
    for (u32 m = 0; m < SR; m++) {
        b[4*(SR+m)]=yo[4*m]; b[4*(SR+m)+1]=yo[4*m+1]; b[4*(SR+m)+2]=yo[4*m+2]; b[4*(SR+m)+3]=yo[4*m+3];
    }
}

/* One ROMix pass for candidate gid, pass `pass`: private uint4 block, V as
 * __global uint4*, TMTO lookup-gap walk. Identical semantics to OpenCL romix_p.*/
__device__ __forceinline__ void romix_p(u32 *gB, uint4 *gV,
    u32 pass, u32 N, u32 gap, u32 NL, u32 gid)
{
    u32 pbase = pass * BWORDS;
    uint4 b[BWORDS4], yo[YO4], t[BWORDS4];
    for (u32 q = 0; q < BWORDS4; q++)
        b[q] = make_uint4(gB[(pbase+4*q  )*NL+gid], gB[(pbase+4*q+1)*NL+gid],
                          gB[(pbase+4*q+2)*NL+gid], gB[(pbase+4*q+3)*NL+gid]);
    for (u32 i = 0; i < N; i++) {
        if (i % gap == 0) {
            u32 s = i / gap;
            for (u32 q = 0; q < BWORDS4; q++) gV[(s*BWORDS4 + q)*NL + gid] = b[q];
        }
        blockmix_p(b, yo);
    }
    for (u32 i = 0; i < N; i++) {
        u32 j = b[4*(2*SR-1)].x & (N - 1);
        u32 s = j / gap, steps = j - s * gap;
        for (u32 q = 0; q < BWORDS4; q++) t[q] = gV[(s*BWORDS4 + q)*NL + gid];
        for (u32 st = 0; st < steps; st++) blockmix_p(t, yo);
        for (u32 q = 0; q < BWORDS4; q++) {
            uint4 tv = t[q], bv = b[q];
            b[q] = make_uint4(bv.x^tv.x, bv.y^tv.y, bv.z^tv.z, bv.w^tv.w);
        }
        blockmix_p(b, yo);
    }
    for (u32 q = 0; q < BWORDS4; q++) {
        gB[(pbase+4*q  )*NL+gid] = b[q].x; gB[(pbase+4*q+1)*NL+gid] = b[q].y;
        gB[(pbase+4*q+2)*NL+gid] = b[q].z; gB[(pbase+4*q+3)*NL+gid] = b[q].w;
    }
}

/* One thread per candidate; PP ROMix passes in place on gB. TPB=32 optimal. */
extern "C" __global__ void scrypt_romix_cuda(
    u32 *gB, uint4 *gV, u32 N, u32 gap, u32 NL, u32 PP)
{
    u32 gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= NL) return;
    for (u32 pass = 0; pass < PP; pass++)
        romix_p(gB, gV, pass, N, gap, NL, gid);
}
