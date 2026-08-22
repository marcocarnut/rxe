/* rxe38 CUDA backend #2 (included into rxe38.c under RXE38_BACKEND_CUDA).
 *
 * Hybrid: PBKDF2/HMAC + AES/secp/verify on the host (reusing rxe38.c's code),
 * ROMix on the GPU via an NVRTC-compiled kernel (scrypt_cuda.cu). Romix is
 * ~99.99% of the work and nvrtc/ptxas compiles it ~22% faster than NVIDIA's
 * OpenCL JIT on sm_120 (Blackwell) -- the route past the OpenCL ceiling to
 * >1 KH/s. Gated byte-exact vs rxe38.c's CPU oracle romix at N=512 AND 16384.
 *
 * Reuses from rxe38.c: romix(), pbkdf2_hmac_sha256_c1(), now_sec(), the GPU_*
 * constants, and (later) bip38_finish/verify + the double-buffered verify path. */

#include <nvrtc.h>
#include <cuda.h>
#include "scrypt_cuda_embed.h"        /* SCRYPT_CUDA: the kernel source string */

#define NVR(x) do{ nvrtcResult _r=(x); if(_r!=NVRTC_SUCCESS){ \
    fprintf(stderr,"rxe38 cuda: NVRTC %s:%d: %s\n",__FILE__,__LINE__,nvrtcGetErrorString(_r)); \
    return -1; } }while(0)
#define CU(x) do{ CUresult _r=(x); if(_r!=CUDA_SUCCESS){ const char*_s=0; cuGetErrorString(_r,&_s); \
    fprintf(stderr,"rxe38 cuda: CU %s:%d: %s\n",__FILE__,__LINE__,_s?_s:"?"); \
    return -1; } }while(0)

struct cuda_gpu {
    CUcontext  ctx;
    CUmodule   mod;
    CUfunction romix;               /* scrypt_romix_cuda */
    char       devname[128];
    int        cc_major, cc_minor;
};

/* Compile scrypt_cuda.cu for compute_89 (PTX; the sm_120 driver JITs it forward-
 * compatibly), load the module, fetch the kernel. Returns 0 / -1. */
static int cuda_setup(struct cuda_gpu *g)
{
    memset(g, 0, sizeof *g);
    char sr[32];
    snprintf(sr, sizeof sr, "-D SR=%d", GPU_R);
    const char *opts[] = { "--gpu-architecture=compute_89", sr };

    nvrtcProgram prog;
    NVR(nvrtcCreateProgram(&prog, SCRYPT_CUDA, "scrypt_cuda.cu", 0, 0, 0));
    nvrtcResult cr = nvrtcCompileProgram(prog, 2, opts);
    size_t logn = 0; nvrtcGetProgramLogSize(prog, &logn);
    if (logn > 1) {
        char *log = malloc(logn); nvrtcGetProgramLog(prog, log);
        fprintf(stderr, "rxe38 cuda: NVRTC log:\n%s\n", log); free(log);
    }
    if (cr != NVRTC_SUCCESS) { fprintf(stderr, "rxe38 cuda: kernel compile failed\n"); return -1; }
    size_t ptxn = 0; NVR(nvrtcGetPTXSize(prog, &ptxn));
    char *ptx = malloc(ptxn); NVR(nvrtcGetPTX(prog, ptx));
    nvrtcDestroyProgram(&prog);

    CU(cuInit(0));
    CUdevice dev;
    CU(cuDeviceGet(&dev, 0));
    cuDeviceGetName(g->devname, sizeof g->devname, dev);
    cuDeviceGetAttribute(&g->cc_major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, dev);
    cuDeviceGetAttribute(&g->cc_minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, dev);
    CU(cuCtxCreate(&g->ctx, 0, dev));
    CU(cuModuleLoadDataEx(&g->mod, ptx, 0, 0, 0));
    CU(cuModuleGetFunction(&g->romix, g->mod, "scrypt_romix_cuda"));
    free(ptx);
    return 0;
}

static void cuda_teardown(struct cuda_gpu *g)
{
    if (g->mod) cuModuleUnload(g->mod);
    if (g->ctx) cuCtxDestroy(g->ctx);
}

/* --cuda-romix-test [N] [gap]: run scrypt_romix_cuda standalone over a batch of
 * candidate slots (PP=GPU_P passes each, lane-interleaved gB), byte-exact-check
 * vs rxe38.c's CPU oracle romix, and time it. The step-1 gate for the backend. */
static int cuda_romix_test(unsigned N, unsigned gap)
{
    struct cuda_gpu g;
    if (cuda_setup(&g) != 0) return 1;
    const unsigned PP = GPU_P, W = GPU_BLK / 4;           /* 256 words/block */
    if (gap < 1) gap = 1;
    unsigned vslots = (N + gap - 1) / gap;

    size_t freeb = 0, totalb = 0;
    cuMemGetInfo(&freeb, &totalb);
    size_t vbytes = (size_t)vslots * (W/4) * 16;          /* V per candidate (uint4) */
    size_t ncand = (size_t)((double)totalb * 0.85 / vbytes);
    if (getenv("RXE38_ROMIX_NC")) ncand = strtoul(getenv("RXE38_ROMIX_NC"), 0, 0);
    unsigned tpb = 32;
    if (getenv("RXE38_CUDA_TPB")) tpb = (unsigned)strtoul(getenv("RXE38_CUDA_TPB"), 0, 0);
    ncand -= ncand % tpb; if (ncand < tpb) ncand = tpb;
    printf("rxe38 cuda romix-only: device=%s (sm_%d%d)  N=%u gap=%u  candidates=%zu (%.1f GB V)  TPB=%u PP=%u\n",
           g.devname, g.cc_major, g.cc_minor, N, gap, ncand, ncand*(double)vbytes/1e9, tpb, PP);

    size_t iowords = ncand * PP * W;
    uint32_t *hin = malloc(iowords*4), *hout = malloc(iowords*4);
    uint32_t seed = 0x1234567u;
    for (size_t i = 0; i < iowords; i++) { seed = seed*1664525u+1013904223u; hin[i] = seed; }

    CUdeviceptr dB, dV;
    CU(cuMemAlloc(&dB, iowords*4));
    CU(cuMemAlloc(&dV, ncand*vbytes));
    unsigned uN=N, ug=gap, unl=(unsigned)ncand, upp=PP;
    void *args[] = { &dB, &dV, &uN, &ug, &unl, &upp };
    unsigned grid = ((unsigned)ncand + tpb - 1) / tpb;

    CU(cuMemcpyHtoD(dB, hin, iowords*4));                 /* warmup launch */
    CU(cuLaunchKernel(g.romix, grid,1,1, tpb,1,1, 0,0, args, 0));
    CU(cuCtxSynchronize());
    CU(cuMemcpyHtoD(dB, hin, iowords*4));                 /* fresh fill, timed run */
    double t0 = now_sec();
    CU(cuLaunchKernel(g.romix, grid,1,1, tpb,1,1, 0,0, args, 0));
    CU(cuCtxSynchronize());
    double dt = now_sec() - t0;
    CU(cuMemcpyDtoH(hout, dB, iowords*4));
    cuMemFree(dB); cuMemFree(dV);

    size_t CHK = ncand < 8 ? ncand : 8;
    uint32_t *V = malloc((size_t)N*W*4), *Y = malloc(W*4), B[256];
    int ok = 1;
    for (size_t c = 0; c < CHK && ok; c++)
        for (unsigned pass = 0; pass < PP; pass++) {
            for (unsigned w = 0; w < W; w++) B[w] = hin[((size_t)(pass*W+w))*ncand + c];
            romix(B, GPU_R, N, V, Y);
            for (unsigned w = 0; w < W; w++)
                if (B[w] != hout[((size_t)(pass*W+w))*ncand + c]) {
                    printf("[FAIL] cand %zu pass %u word %u: cpu %08x gpu %08x\n",
                           c, pass, w, B[w], hout[((size_t)(pass*W+w))*ncand + c]);
                    ok = 0; break;
                }
            if (!ok) break;
        }
    free(V); free(Y); free(hin); free(hout);
    cuda_teardown(&g);

    printf("cuda romix-only: %s | %.3fs | %.1f passes/s | %.1f cand-equiv/s (/%u) | OpenCL-full ~911, target >1000\n",
           ok ? "BYTE-EXACT vs CPU oracle romix" : "FAILED", dt,
           ncand*(double)PP/dt, (double)ncand/dt, PP);
    return ok ? 0 : 1;
}
