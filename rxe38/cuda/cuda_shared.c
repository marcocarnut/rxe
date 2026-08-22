/* CUDA scalar ROMix with the working block b + yo scratch in __shared__ (100KB
 * opt-in, compute 8.9). Interleaved layout smem[k*TPB + tid] = bank-friendly.
 * t (walk block) stays in local. Byte-exact vs rxe38.c oracle. K=1. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <nvrtc.h>
#include <cuda.h>
#define NVRTC(x) do{ nvrtcResult r=(x); if(r!=NVRTC_SUCCESS){fprintf(stderr,"NVRTC %d %s\n",__LINE__,nvrtcGetErrorString(r));exit(1);} }while(0)
#define CU(x) do{ CUresult r=(x); if(r!=CUDA_SUCCESS){const char*s;cuGetErrorString(r,&s);fprintf(stderr,"CU %d %s\n",__LINE__,s);exit(1);} }while(0)
#define ROTL32(a,b) (((a)<<(b))|((a)>>(32-(b))))
static void salsa20_8(uint32_t B[16]){ uint32_t x[16]; for(int i=0;i<16;i++)x[i]=B[i];
 for(int i=0;i<8;i+=2){
  x[4]^=ROTL32(x[0]+x[12],7);x[8]^=ROTL32(x[4]+x[0],9);x[12]^=ROTL32(x[8]+x[4],13);x[0]^=ROTL32(x[12]+x[8],18);
  x[9]^=ROTL32(x[5]+x[1],7);x[13]^=ROTL32(x[9]+x[5],9);x[1]^=ROTL32(x[13]+x[9],13);x[5]^=ROTL32(x[1]+x[13],18);
  x[14]^=ROTL32(x[10]+x[6],7);x[2]^=ROTL32(x[14]+x[10],9);x[6]^=ROTL32(x[2]+x[14],13);x[10]^=ROTL32(x[6]+x[2],18);
  x[3]^=ROTL32(x[15]+x[11],7);x[7]^=ROTL32(x[3]+x[15],9);x[11]^=ROTL32(x[7]+x[3],13);x[15]^=ROTL32(x[11]+x[7],18);
  x[1]^=ROTL32(x[0]+x[3],7);x[2]^=ROTL32(x[1]+x[0],9);x[3]^=ROTL32(x[2]+x[1],13);x[0]^=ROTL32(x[3]+x[2],18);
  x[6]^=ROTL32(x[5]+x[4],7);x[7]^=ROTL32(x[6]+x[5],9);x[4]^=ROTL32(x[7]+x[6],13);x[5]^=ROTL32(x[4]+x[7],18);
  x[11]^=ROTL32(x[10]+x[9],7);x[8]^=ROTL32(x[11]+x[10],9);x[9]^=ROTL32(x[8]+x[11],13);x[10]^=ROTL32(x[9]+x[8],18);
  x[12]^=ROTL32(x[15]+x[14],7);x[13]^=ROTL32(x[12]+x[15],9);x[14]^=ROTL32(x[13]+x[12],13);x[15]^=ROTL32(x[14]+x[13],18);}
 for(int i=0;i<16;i++)B[i]+=x[i]; }
static void blockmix(uint32_t*B,uint32_t*Y,int r){ uint32_t X[16]; memcpy(X,B+(2*r-1)*16,64);
 for(int i=0;i<2*r;i++){for(int k=0;k<16;k++)X[k]^=B[i*16+k];salsa20_8(X);memcpy(Y+i*16,X,64);}
 for(int i=0;i<r;i++)memcpy(B+i*16,Y+(2*i)*16,64); for(int i=0;i<r;i++)memcpy(B+(r+i)*16,Y+(2*i+1)*16,64);}
static void romix(uint32_t*B,int r,uint32_t N,uint32_t*V,uint32_t*Y){ size_t w=32*(size_t)r;
 for(uint32_t i=0;i<N;i++){memcpy(V+i*w,B,w*4);blockmix(B,Y,r);}
 for(uint32_t i=0;i<N;i++){uint32_t j=B[(2*r-1)*16]&(N-1);for(size_t k=0;k<w;k++)B[k]^=V[j*w+k];blockmix(B,Y,r);}}

static const char *KSRC =
"#define SR 8u\n#define BWORDS4 64u\n#define YO4 32u\n"
"#define R32(a,b) (((a)<<(b))|((a)>>(32u-(b))))\n typedef unsigned u32;\n"
"__device__ __forceinline__ void salsa(u32 X[16]){ u32 x[16];\n"
" #pragma unroll\n for(int i=0;i<16;i++)x[i]=X[i];\n #pragma unroll\n for(int i=0;i<8;i+=2){\n"
"  x[4]^=R32(x[0]+x[12],7);x[8]^=R32(x[4]+x[0],9);x[12]^=R32(x[8]+x[4],13);x[0]^=R32(x[12]+x[8],18);\n"
"  x[9]^=R32(x[5]+x[1],7);x[13]^=R32(x[9]+x[5],9);x[1]^=R32(x[13]+x[9],13);x[5]^=R32(x[1]+x[13],18);\n"
"  x[14]^=R32(x[10]+x[6],7);x[2]^=R32(x[14]+x[10],9);x[6]^=R32(x[2]+x[14],13);x[10]^=R32(x[6]+x[2],18);\n"
"  x[3]^=R32(x[15]+x[11],7);x[7]^=R32(x[3]+x[15],9);x[11]^=R32(x[7]+x[3],13);x[15]^=R32(x[11]+x[7],18);\n"
"  x[1]^=R32(x[0]+x[3],7);x[2]^=R32(x[1]+x[0],9);x[3]^=R32(x[2]+x[1],13);x[0]^=R32(x[3]+x[2],18);\n"
"  x[6]^=R32(x[5]+x[4],7);x[7]^=R32(x[6]+x[5],9);x[4]^=R32(x[7]+x[6],13);x[5]^=R32(x[4]+x[7],18);\n"
"  x[11]^=R32(x[10]+x[9],7);x[8]^=R32(x[11]+x[10],9);x[9]^=R32(x[8]+x[11],13);x[10]^=R32(x[9]+x[8],18);\n"
"  x[12]^=R32(x[15]+x[14],7);x[13]^=R32(x[12]+x[15],9);x[14]^=R32(x[13]+x[12],13);x[15]^=R32(x[14]+x[13],18);}\n"
" #pragma unroll\n for(int i=0;i<16;i++)X[i]+=x[i];\n}\n"
/* b,yo are shared bases already offset by tid; stride S=blockDim between quartets */
"__device__ __forceinline__ void blockmix_sh(uint4* b, uint4* yo, u32 S){\n"
" u32 X[16];\n"
" { uint4 q0=b[(4*(2*SR-1))*S],q1=b[(4*(2*SR-1)+1)*S],q2=b[(4*(2*SR-1)+2)*S],q3=b[(4*(2*SR-1)+3)*S];\n"
"   X[0]=q0.x;X[1]=q0.y;X[2]=q0.z;X[3]=q0.w;X[4]=q1.x;X[5]=q1.y;X[6]=q1.z;X[7]=q1.w;\n"
"   X[8]=q2.x;X[9]=q2.y;X[10]=q2.z;X[11]=q2.w;X[12]=q3.x;X[13]=q3.y;X[14]=q3.z;X[15]=q3.w; }\n"
" #pragma unroll 1\n for(u32 i=0;i<2*SR;i++){\n"
"   uint4 q0=b[(4*i)*S],q1=b[(4*i+1)*S],q2=b[(4*i+2)*S],q3=b[(4*i+3)*S];\n"
"   X[0]^=q0.x;X[1]^=q0.y;X[2]^=q0.z;X[3]^=q0.w;X[4]^=q1.x;X[5]^=q1.y;X[6]^=q1.z;X[7]^=q1.w;\n"
"   X[8]^=q2.x;X[9]^=q2.y;X[10]^=q2.z;X[11]^=q2.w;X[12]^=q3.x;X[13]^=q3.y;X[14]^=q3.z;X[15]^=q3.w;\n"
"   salsa(X);\n"
"   uint4 o0=make_uint4(X[0],X[1],X[2],X[3]),o1=make_uint4(X[4],X[5],X[6],X[7]),\n"
"         o2=make_uint4(X[8],X[9],X[10],X[11]),o3=make_uint4(X[12],X[13],X[14],X[15]);\n"
"   u32 m=i>>1;\n"
"   if((i&1)==0){b[(4*m)*S]=o0;b[(4*m+1)*S]=o1;b[(4*m+2)*S]=o2;b[(4*m+3)*S]=o3;}\n"
"   else        {yo[(4*m)*S]=o0;yo[(4*m+1)*S]=o1;yo[(4*m+2)*S]=o2;yo[(4*m+3)*S]=o3;}\n"
" }\n"
" #pragma unroll 1\n for(u32 m=0;m<SR;m++){b[(4*(SR+m))*S]=yo[(4*m)*S];b[(4*(SR+m)+1)*S]=yo[(4*m+1)*S];b[(4*(SR+m)+2)*S]=yo[(4*m+2)*S];b[(4*(SR+m)+3)*S]=yo[(4*m+3)*S];}\n"
"}\n"
/* t is local; walk uses a local-block blockmix that reads yo from shared. */
"__device__ __forceinline__ void blockmix_lt(uint4* b, uint4* yo, u32 S){\n"
" u32 X[16];\n"
" { uint4 q0=b[4*(2*SR-1)],q1=b[4*(2*SR-1)+1],q2=b[4*(2*SR-1)+2],q3=b[4*(2*SR-1)+3];\n"
"   X[0]=q0.x;X[1]=q0.y;X[2]=q0.z;X[3]=q0.w;X[4]=q1.x;X[5]=q1.y;X[6]=q1.z;X[7]=q1.w;\n"
"   X[8]=q2.x;X[9]=q2.y;X[10]=q2.z;X[11]=q2.w;X[12]=q3.x;X[13]=q3.y;X[14]=q3.z;X[15]=q3.w; }\n"
" #pragma unroll 1\n for(u32 i=0;i<2*SR;i++){\n"
"   uint4 q0=b[4*i],q1=b[4*i+1],q2=b[4*i+2],q3=b[4*i+3];\n"
"   X[0]^=q0.x;X[1]^=q0.y;X[2]^=q0.z;X[3]^=q0.w;X[4]^=q1.x;X[5]^=q1.y;X[6]^=q1.z;X[7]^=q1.w;\n"
"   X[8]^=q2.x;X[9]^=q2.y;X[10]^=q2.z;X[11]^=q2.w;X[12]^=q3.x;X[13]^=q3.y;X[14]^=q3.z;X[15]^=q3.w;\n"
"   salsa(X);\n"
"   uint4 o0=make_uint4(X[0],X[1],X[2],X[3]),o1=make_uint4(X[4],X[5],X[6],X[7]),\n"
"         o2=make_uint4(X[8],X[9],X[10],X[11]),o3=make_uint4(X[12],X[13],X[14],X[15]);\n"
"   u32 m=i>>1;\n"
"   if((i&1)==0){b[4*m]=o0;b[4*m+1]=o1;b[4*m+2]=o2;b[4*m+3]=o3;}\n"
"   else        {yo[(4*m)*S]=o0;yo[(4*m+1)*S]=o1;yo[(4*m+2)*S]=o2;yo[(4*m+3)*S]=o3;}\n"
" }\n"
" #pragma unroll 1\n for(u32 m=0;m<SR;m++){b[4*(SR+m)]=yo[(4*m)*S];b[4*(SR+m)+1]=yo[(4*m+1)*S];b[4*(SR+m)+2]=yo[(4*m+2)*S];b[4*(SR+m)+3]=yo[(4*m+3)*S];}\n"
"}\n"
"extern \"C\" __global__ void romix_sh(const u32* gIn, uint4* gV, u32* gOut, u32 N, u32 gap, u32 NC){\n"
"  extern __shared__ uint4 smem[];\n"
"  u32 tid=blockIdx.x*blockDim.x+threadIdx.x;\n"
"  if(tid>=NC) return;\n"
"  u32 S=blockDim.x;\n"
"  uint4* b  = smem + threadIdx.x;\n"                       /* b: quartet k at [k*S] */
"  uint4* yo = smem + (u32)BWORDS4*S + threadIdx.x;\n"
"  uint4 t[BWORDS4];\n"
"  #pragma unroll\n  for(u32 q=0;q<BWORDS4;q++)\n"
"    b[q*S]=make_uint4(gIn[(4*q+0)*NC+tid],gIn[(4*q+1)*NC+tid],gIn[(4*q+2)*NC+tid],gIn[(4*q+3)*NC+tid]);\n"
"  for(u32 i=0;i<N;i++){\n"
"    if(i%gap==0){ u32 s=i/gap; for(u32 q=0;q<BWORDS4;q++) gV[(s*BWORDS4+q)*NC+tid]=b[q*S]; }\n"
"    blockmix_sh(b,yo,S);\n"
"  }\n"
"  for(u32 i=0;i<N;i++){\n"
"    u32 j=b[(4*(2*SR-1))*S].x&(N-1u); u32 s=j/gap, steps=j-s*gap;\n"
"    for(u32 q=0;q<BWORDS4;q++) t[q]=gV[(s*BWORDS4+q)*NC+tid];\n"
"    for(u32 st=0;st<steps;st++) blockmix_lt(t,yo,S);\n"
"    for(u32 q=0;q<BWORDS4;q++){ uint4 tv=t[q],bv=b[q*S]; b[q*S]=make_uint4(bv.x^tv.x,bv.y^tv.y,bv.z^tv.z,bv.w^tv.w); }\n"
"    blockmix_sh(b,yo,S);\n"
"  }\n"
"  for(u32 q=0;q<BWORDS4;q++){ uint4 v=b[q*S]; gOut[(4*q+0)*NC+tid]=v.x;gOut[(4*q+1)*NC+tid]=v.y;gOut[(4*q+2)*NC+tid]=v.z;gOut[(4*q+3)*NC+tid]=v.w; }\n"
"}\n";
static unsigned rng=0xBEEF01u; static unsigned rr(void){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;}
static double now(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
int main(int argc,char**argv){
  unsigned N=argc>1?(unsigned)strtoul(argv[1],0,0):512u;
  unsigned gap=argc>2?(unsigned)strtoul(argv[2],0,0):1u;
  int T=argc>3?atoi(argv[3]):0; int TPB=argc>4?atoi(argv[4]):32;
  const int BW=256; int perf=T>0; int NC=perf?T:8;
  nvrtcProgram prog;NVRTC(nvrtcCreateProgram(&prog,KSRC,"k.cu",0,0,0));
  const char*opts[]={"--gpu-architecture=compute_89"};
  nvrtcResult cr=nvrtcCompileProgram(prog,1,opts);
  size_t lg;NVRTC(nvrtcGetProgramLogSize(prog,&lg));if(lg>1){char*b=malloc(lg);nvrtcGetProgramLog(prog,b);fprintf(stderr,"%s",b);free(b);}
  if(cr!=NVRTC_SUCCESS)return 1;
  size_t psz;NVRTC(nvrtcGetPTXSize(prog,&psz));char*ptx=malloc(psz);NVRTC(nvrtcGetPTX(prog,ptx));
  CU(cuInit(0));CUdevice dev;CU(cuDeviceGet(&dev,0));CUcontext ctx;CU(cuCtxCreate(&ctx,0,dev));
  CUmodule mod;CU(cuModuleLoadDataEx(&mod,ptx,0,0,0));CUfunction fn;CU(cuModuleGetFunction(&fn,mod,"romix_sh"));
  unsigned shbytes=(64u+32u)*TPB*16u;   /* (BWORDS4+YO4) uint4 * TPB */
  CU(cuFuncSetAttribute(fn,CU_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES,shbytes));
  size_t inw=(size_t)NC*BW; uint32_t*h_in=malloc(inw*4),*h_out=malloc(inw*4);
  for(size_t i=0;i<inw;i++)h_in[i]=rr();
  CUdeviceptr d_in,d_out,d_V; size_t vslots=(N+gap-1)/gap;
  CU(cuMemAlloc(&d_in,inw*4));CU(cuMemAlloc(&d_out,inw*4));CU(cuMemAlloc(&d_V,vslots*BW*(size_t)NC*4));
  CU(cuMemcpyHtoD(d_in,h_in,inw*4));
  unsigned uN=N,ugap=gap,uNC=NC; void*args[]={&d_in,&d_V,&d_out,&uN,&ugap,&uNC};
  int grid=(NC+TPB-1)/TPB;
  if(!perf){
    CU(cuLaunchKernel(fn,grid,1,1,TPB,1,1,shbytes,0,args,0));CU(cuCtxSynchronize());
    CU(cuMemcpyDtoH(h_out,d_out,inw*4));
    uint32_t*V=malloc((size_t)N*BW*4),*Y=malloc(BW*4),blk[256]; int bad=0;
    for(int c=0;c<NC&&bad<8;c++){ for(int w=0;w<BW;w++)blk[w]=h_in[(size_t)w*NC+c]; romix(blk,8,N,V,Y);
      for(int w=0;w<BW;w++){uint32_t g=h_out[(size_t)w*NC+c]; if(g!=blk[w]){fprintf(stderr,"c%d w%d gpu %08x exp %08x\n",c,w,g,blk[w]);bad++;if(bad>=8)break;}} }
    printf("CUDA shared gap=%u N=%u NC=%d shmem=%uB/blk TPB=%d: %s\n",gap,N,NC,shbytes,TPB,bad?"FAIL":"BYTE-EXACT PASS");
    return bad?1:0;
  } else {
    size_t vbytes=vslots*BW*(size_t)NC*4;
    CU(cuLaunchKernel(fn,grid,1,1,TPB,1,1,shbytes,0,args,0));CU(cuCtxSynchronize());
    double t0=now();int iters=3; for(int it=0;it<iters;it++)CU(cuLaunchKernel(fn,grid,1,1,TPB,1,1,shbytes,0,args,0));
    CU(cuCtxSynchronize());double dt=(now()-t0)/iters; double rs=NC/dt;
    printf("SHARED gap=%u N=%u T=%d TPB=%d shmem=%uKB/blk V=%.1fGB  %.4fs  %.1f romix/s => %.1f cand-equiv/s\n",
      gap,N,T,TPB,shbytes/1024,vbytes/1e9,dt,rs,rs/8.0);
    return 0;
  }
}
