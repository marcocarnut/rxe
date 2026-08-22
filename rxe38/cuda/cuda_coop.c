/* CUDA cooperative ROMix (T=4, __shfl_sync transpose) -- byte-exact gate vs
 * rxe38.c's oracle romix. SR=8 (r=8). One ROMix pass per launch (PP=1,pass=0
 * for this test). Kernel string is NVRTC-compiled for compute_89. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <nvrtc.h>
#include <cuda.h>

#define NVRTC(x) do{ nvrtcResult r=(x); if(r!=NVRTC_SUCCESS){ \
  fprintf(stderr,"NVRTC %s:%d: %s\n",__FILE__,__LINE__,nvrtcGetErrorString(r)); exit(1);} }while(0)
#define CU(x) do{ CUresult r=(x); if(r!=CUDA_SUCCESS){ const char*s; cuGetErrorString(r,&s); \
  fprintf(stderr,"CU %s:%d: %s\n",__FILE__,__LINE__,s); exit(1);} }while(0)

/* ================= ORACLE (byte-exact copy from rxe38.c) ================= */
#define ROTL32(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
static void salsa20_8(uint32_t B[16]){
    uint32_t x[16];
    for (int i=0;i<16;i++) x[i]=B[i];
    for (int i=0;i<8;i+=2){
        x[ 4]^=ROTL32(x[ 0]+x[12], 7); x[ 8]^=ROTL32(x[ 4]+x[ 0], 9);
        x[12]^=ROTL32(x[ 8]+x[ 4],13); x[ 0]^=ROTL32(x[12]+x[ 8],18);
        x[ 9]^=ROTL32(x[ 5]+x[ 1], 7); x[13]^=ROTL32(x[ 9]+x[ 5], 9);
        x[ 1]^=ROTL32(x[13]+x[ 9],13); x[ 5]^=ROTL32(x[ 1]+x[13],18);
        x[14]^=ROTL32(x[10]+x[ 6], 7); x[ 2]^=ROTL32(x[14]+x[10], 9);
        x[ 6]^=ROTL32(x[ 2]+x[14],13); x[10]^=ROTL32(x[ 6]+x[ 2],18);
        x[ 3]^=ROTL32(x[15]+x[11], 7); x[ 7]^=ROTL32(x[ 3]+x[15], 9);
        x[11]^=ROTL32(x[ 7]+x[ 3],13); x[15]^=ROTL32(x[11]+x[ 7],18);
        x[ 1]^=ROTL32(x[ 0]+x[ 3], 7); x[ 2]^=ROTL32(x[ 1]+x[ 0], 9);
        x[ 3]^=ROTL32(x[ 2]+x[ 1],13); x[ 0]^=ROTL32(x[ 3]+x[ 2],18);
        x[ 6]^=ROTL32(x[ 5]+x[ 4], 7); x[ 7]^=ROTL32(x[ 6]+x[ 5], 9);
        x[ 4]^=ROTL32(x[ 7]+x[ 6],13); x[ 5]^=ROTL32(x[ 4]+x[ 7],18);
        x[11]^=ROTL32(x[10]+x[ 9], 7); x[ 8]^=ROTL32(x[11]+x[10], 9);
        x[ 9]^=ROTL32(x[ 8]+x[11],13); x[10]^=ROTL32(x[ 9]+x[ 8],18);
        x[12]^=ROTL32(x[15]+x[14], 7); x[13]^=ROTL32(x[12]+x[15], 9);
        x[14]^=ROTL32(x[13]+x[12],13); x[15]^=ROTL32(x[14]+x[13],18);
    }
    for (int i=0;i<16;i++) B[i]+=x[i];
}
static void blockmix(uint32_t *B, uint32_t *Y, int r){
    uint32_t X[16]; memcpy(X, B+(2*r-1)*16, 64);
    for (int i=0;i<2*r;i++){ for(int k=0;k<16;k++) X[k]^=B[i*16+k]; salsa20_8(X); memcpy(Y+i*16,X,64); }
    for (int i=0;i<r;i++) memcpy(B+i*16,       Y+(2*i)*16,   64);
    for (int i=0;i<r;i++) memcpy(B+(r+i)*16,   Y+(2*i+1)*16, 64);
}
static void romix(uint32_t *B, int r, uint32_t N, uint32_t *V, uint32_t *Y){
    size_t words=32*(size_t)r;
    for (uint32_t i=0;i<N;i++){ memcpy(V+i*words,B,words*4); blockmix(B,Y,r); }
    for (uint32_t i=0;i<N;i++){ uint32_t j=B[(2*r-1)*16]&(N-1);
        for(size_t k=0;k<words;k++) B[k]^=V[j*words+k]; blockmix(B,Y,r); }
}

/* ================= CUDA COOP KERNEL (NVRTC source) ================= */
static const char *KSRC =
"#define SR 8u\n"
"#define BWORDS (32u*SR)\n"
"#define COOPW  (BWORDS/4u)\n"          /* 64 */
"#define R32(a,b) (((a)<<(b))|((a)>>(32u-(b))))\n"
"__device__ __forceinline__ void cqr(unsigned w[4], unsigned st){\n"
"  unsigned a=w[st&3u],b=w[(st+1u)&3u],c=w[(st+2u)&3u],d=w[(st+3u)&3u];\n"
"  b^=R32(a+d,7u); c^=R32(b+a,9u); d^=R32(c+b,13u); a^=R32(d+c,18u);\n"
"  w[st&3u]=a; w[(st+1u)&3u]=b; w[(st+2u)&3u]=c; w[(st+3u)&3u]=d;\n"
"}\n"
/* 4x4 transpose across the 4 lanes: out_lt[k]=in_k[lt], in 4 shuffles.
 * pre-rotate regs by lt (explicit selects, no register-array spill), one shuffle
 * per slot with a per-lane source, post-rotate back. */
"__device__ __forceinline__ void tr4(unsigned v[4], unsigned base, unsigned lt){\n"
"  unsigned v0=v[0],v1=v[1],v2=v[2],v3=v[3];\n"
"  unsigned t0=(lt==0u)?v0:(lt==1u)?v1:(lt==2u)?v2:v3;\n"
"  unsigned t1=(lt==0u)?v1:(lt==1u)?v2:(lt==2u)?v3:v0;\n"
"  unsigned t2=(lt==0u)?v2:(lt==1u)?v3:(lt==2u)?v0:v1;\n"
"  unsigned t3=(lt==0u)?v3:(lt==1u)?v0:(lt==2u)?v1:v2;\n"
"  unsigned u0=__shfl_sync(0xffffffffu,t0,base+((lt   )&3u),32);\n"
"  unsigned u1=__shfl_sync(0xffffffffu,t1,base+((lt-1u)&3u),32);\n"
"  unsigned u2=__shfl_sync(0xffffffffu,t2,base+((lt-2u)&3u),32);\n"
"  unsigned u3=__shfl_sync(0xffffffffu,t3,base+((lt-3u)&3u),32);\n"
"  v[0]=(lt==0u)?u0:(lt==1u)?u1:(lt==2u)?u2:u3;\n"
"  v[1]=(lt==0u)?u3:(lt==1u)?u0:(lt==2u)?u1:u2;\n"
"  v[2]=(lt==0u)?u2:(lt==1u)?u3:(lt==2u)?u0:u1;\n"
"  v[3]=(lt==0u)?u1:(lt==1u)?u2:(lt==2u)?u3:u0;\n"
"}\n"
"__device__ __forceinline__ void salsa_coop(unsigned Xc[4], unsigned base, unsigned lt){\n"
"  unsigned in0=Xc[0],in1=Xc[1],in2=Xc[2],in3=Xc[3];\n"
"  for(int dr=0;dr<4;dr++){\n"
"    cqr(Xc, lt);\n"                    /* column round */
"    tr4(Xc, base, lt);\n"             /* -> rows      */
"    cqr(Xc, lt);\n"                    /* row round    */
"    tr4(Xc, base, lt);\n"             /* -> columns   */
"  }\n"
"  Xc[0]+=in0; Xc[1]+=in1; Xc[2]+=in2; Xc[3]+=in3;\n"   /* feedforward */
"}\n"
"__device__ __forceinline__ void blockmix_coop(unsigned *bl, unsigned base, unsigned lt){\n"
"  unsigned Xc[4], Yc[COOPW];\n"
"  for(int r=0;r<4;r++) Xc[r]=bl[(2u*SR-1u)*4u+r];\n"
"  for(unsigned i=0;i<2u*SR;i++){\n"
"    for(int r=0;r<4;r++) Xc[r]^=bl[i*4u+r];\n"
"    salsa_coop(Xc, base, lt);\n"
"    for(int r=0;r<4;r++) Yc[i*4u+r]=Xc[r];\n"
"  }\n"
"  for(unsigned m=0;m<SR;m++) for(int r=0;r<4;r++) bl[m*4u+r]        = Yc[(2u*m)*4u+r];\n"
"  for(unsigned m=0;m<SR;m++) for(int r=0;r<4;r++) bl[(SR+m)*4u+r]   = Yc[(2u*m+1u)*4u+r];\n"
"}\n"
"extern \"C\" __global__ void romix_coop(const unsigned* gIn, unsigned* gV,\n"
"     unsigned* gOut, unsigned N, unsigned NLC, unsigned PP, unsigned pass){\n"
"  unsigned gid=blockIdx.x*blockDim.x+threadIdx.x;\n"
"  unsigned cand=gid>>2, lt=gid&3u;\n"
"  unsigned base=(threadIdx.x & 31u) & ~3u;\n"       /* group base within warp */
"  (void)NLC;\n"
"  unsigned bl[COOPW];\n"
"  size_t vbase=(size_t)cand*N*BWORDS;\n"
"  size_t ibase=((size_t)cand*PP+pass)*BWORDS;\n"
"  for(unsigned q=0;q<COOPW;q++) bl[q]=gIn[ibase+4u*q+lt];\n"
"  for(unsigned i=0;i<N;i++){\n"
"    size_t vb=vbase+(size_t)i*BWORDS;\n"
"    for(unsigned q=0;q<COOPW;q++) gV[vb+4u*q+lt]=bl[q];\n"
"    blockmix_coop(bl, base, lt);\n"
"  }\n"
"  for(unsigned i=0;i<N;i++){\n"
"    unsigned jw=__shfl_sync(0xffffffffu, bl[(2u*SR-1u)*4u], base, 32);\n"
"    unsigned j=jw&(N-1u);\n"
"    size_t vb=vbase+(size_t)j*BWORDS;\n"
"    for(unsigned q=0;q<COOPW;q++) bl[q]^=gV[vb+4u*q+lt];\n"
"    blockmix_coop(bl, base, lt);\n"
"  }\n"
"  for(unsigned q=0;q<COOPW;q++) gOut[ibase+4u*q+lt]=bl[q];\n"
"}\n";

static unsigned rng=0x12345678u;
static unsigned rr(void){ rng ^= rng<<13; rng ^= rng>>17; rng ^= rng<<5; return rng; }

int main(int argc, char**argv){
    unsigned N = argc>1 ? (unsigned)strtoul(argv[1],0,0) : 512u;
    const int NLC = 8;              /* 8 candidates = 32 lanes = 1 warp */
    const int BW = 256;             /* BWORDS for r=8 */

    /* compile */
    nvrtcProgram prog;
    NVRTC(nvrtcCreateProgram(&prog, KSRC, "romix_coop.cu", 0,0,0));
    const char *opts[]={"--gpu-architecture=compute_89"};
    nvrtcResult cr=nvrtcCompileProgram(prog,1,opts);
    size_t logsz; NVRTC(nvrtcGetProgramLogSize(prog,&logsz));
    if(logsz>1){ char*l=malloc(logsz); nvrtcGetProgramLog(prog,l); fprintf(stderr,"%s\n",l); free(l);}
    if(cr!=NVRTC_SUCCESS){ fprintf(stderr,"compile failed\n"); return 1; }
    size_t psz; NVRTC(nvrtcGetPTXSize(prog,&psz)); char*ptx=malloc(psz); NVRTC(nvrtcGetPTX(prog,ptx));

    CU(cuInit(0)); CUdevice dev; CU(cuDeviceGet(&dev,0));
    CUcontext ctx; CU(cuCtxCreate(&ctx,0,dev));
    CUmodule mod; CU(cuModuleLoadDataEx(&mod,ptx,0,0,0));
    CUfunction fn; CU(cuModuleGetFunction(&fn,mod,"romix_coop"));

    /* inputs: NLC random blocks */
    size_t inw = (size_t)NLC*BW;
    uint32_t *h_in = malloc(inw*4), *h_out=malloc(inw*4);
    for(size_t i=0;i<inw;i++) h_in[i]=rr();

    /* oracle */
    uint32_t *exp = malloc(inw*4);
    memcpy(exp,h_in,inw*4);
    uint32_t *V=malloc((size_t)N*BW*4), *Y=malloc(BW*4);
    for(int c=0;c<NLC;c++) romix(exp + (size_t)c*BW, 8, N, V, Y);

    /* gpu */
    CUdeviceptr d_in,d_out,d_V;
    CU(cuMemAlloc(&d_in, inw*4)); CU(cuMemAlloc(&d_out, inw*4));
    CU(cuMemAlloc(&d_V, (size_t)NLC*N*BW*4));
    CU(cuMemcpyHtoD(d_in,h_in,inw*4));
    unsigned uN=N, uNLC=NLC, uPP=1, upass=0;
    void*args[]={&d_in,&d_V,&d_out,&uN,&uNLC,&uPP,&upass};
    CU(cuLaunchKernel(fn, 1,1,1, 32,1,1, 0,0, args,0));
    CU(cuCtxSynchronize());
    CU(cuMemcpyDtoH(h_out,d_out,inw*4));

    int bad=0;
    for(size_t i=0;i<inw && bad<8;i++) if(h_out[i]!=exp[i]){
        fprintf(stderr,"mismatch word %zu (cand %zu, w %zu): gpu %08x exp %08x\n",
                i, i/BW, i%BW, h_out[i], exp[i]); bad++; }
    printf("CUDA COOP romix N=%u NLC=%d: %s\n", N, NLC, bad?"FAIL":"BYTE-EXACT PASS");
    return bad?1:0;
}
