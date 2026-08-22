/* NVRTC + __shfl_sync smoke test: runtime-compile a kernel that rotates a
 * value across a 4-lane cooperative group (T=4) via __shfl_sync, launch it,
 * and check the exact result. This is the mechanism the CUDA coop ROMix needs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nvrtc.h>
#include <cuda.h>

#define NVRTC(x) do{ nvrtcResult r=(x); if(r!=NVRTC_SUCCESS){ \
  fprintf(stderr,"NVRTC %s:%d: %s\n",__FILE__,__LINE__,nvrtcGetErrorString(r)); exit(1);} }while(0)
#define CU(x) do{ CUresult r=(x); if(r!=CUDA_SUCCESS){ const char*s; cuGetErrorString(r,&s); \
  fprintf(stderr,"CU %s:%d: %s\n",__FILE__,__LINE__,s); exit(1);} }while(0)

static const char *SRC =
"extern \"C\" __global__ void shflrot(const unsigned* in, unsigned* out, int n){\n"
"  int gid = blockIdx.x*blockDim.x + threadIdx.x;\n"
"  if (gid >= n) return;\n"
"  unsigned v = in[gid];\n"
"  // within each group of 4 lanes, pull the value from (lane+1)%4\n"
"  int lane = threadIdx.x & 3;\n"
"  int src  = (lane + 1) & 3;\n"
"  // full-warp mask; group base = lane & ~3, add src offset\n"
"  int base = threadIdx.x & ~3;\n"
"  unsigned r = __shfl_sync(0xffffffffu, v, base + src, 32);\n"
"  out[gid] = r;\n"
"}\n";

int main(void){
  nvrtcProgram prog;
  NVRTC(nvrtcCreateProgram(&prog, SRC, "shflrot.cu", 0, 0, 0));
  const char *opts[] = { "--gpu-architecture=compute_89" };
  nvrtcResult cr = nvrtcCompileProgram(prog, 1, opts);
  size_t logsz; NVRTC(nvrtcGetProgramLogSize(prog,&logsz));
  if (logsz>1){ char*log=malloc(logsz); nvrtcGetProgramLog(prog,log);
    fprintf(stderr,"--- NVRTC log ---\n%s\n",log); free(log); }
  if (cr!=NVRTC_SUCCESS){ fprintf(stderr,"compile failed\n"); return 1; }
  size_t ptxsz; NVRTC(nvrtcGetPTXSize(prog,&ptxsz));
  char *ptx=malloc(ptxsz); NVRTC(nvrtcGetPTX(prog,ptx));

  CU(cuInit(0));
  CUdevice dev; CU(cuDeviceGet(&dev,0));
  CUcontext ctx; CU(cuCtxCreate(&ctx,0,dev));
  CUmodule mod; CU(cuModuleLoadDataEx(&mod,ptx,0,0,0));
  CUfunction fn; CU(cuModuleGetFunction(&fn,mod,"shflrot"));

  int n=32;
  unsigned h_in[32], h_out[32], h_exp[32];
  for(int i=0;i<n;i++) h_in[i]=100+i;
  for(int i=0;i<n;i++){ int lane=i&3, base=i&~3, src=(lane+1)&3; h_exp[i]=h_in[base+src]; }

  CUdeviceptr d_in,d_out;
  CU(cuMemAlloc(&d_in,n*sizeof(unsigned)));
  CU(cuMemAlloc(&d_out,n*sizeof(unsigned)));
  CU(cuMemcpyHtoD(d_in,h_in,n*sizeof(unsigned)));
  void *args[]={&d_in,&d_out,&n};
  CU(cuLaunchKernel(fn, 1,1,1, 32,1,1, 0,0, args,0));
  CU(cuCtxSynchronize());
  CU(cuMemcpyDtoH(h_out,d_out,n*sizeof(unsigned)));

  int ok=1;
  for(int i=0;i<n;i++) if(h_out[i]!=h_exp[i]){ ok=0;
    fprintf(stderr,"lane %d: got %u exp %u\n",i,h_out[i],h_exp[i]); }
  printf(ok? "SHFL SMOKE: PASS (T=4 rotate byte-exact across 32 lanes)\n"
           : "SHFL SMOKE: FAIL\n");
  return ok?0:1;
}
