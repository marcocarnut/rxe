# rxe38 CUDA experiments — preserved research (NOT built into the shipped binary)

**Status: research artifacts, byte-exact-validated, deliberately NOT productionized.**
The shipped GPU path is the **OpenCL** champion (`rxe38/scrypt.cl`, `--backend opencl`,
the default, ~525 cand/s on an RTX 4080 SUPER, ~27× over the original 19). These
CUDA harnesses were a bounded investigation into whether NVIDIA-specific features
(`__shfl_sync`, `cp.async`, 100 KB `__shared__`) could push past the champion toward
the aspirational 1 KH/s. **They cannot** — see the ceiling story below. They are kept
so the work can be revisited without redoing it. If a CUDA backend #2 is ever built
(`--backend cuda`, `-DRXE38_BACKEND_CUDA`), **`cuda_shared.c`'s kernel is the chosen
design** (fastest measured).

Every harness NVRTC-compiles its kernel for `compute_89` and gates it **byte-exact
against a copy of rxe38.c's oracle `romix`** (the same discipline that gates the OpenCL
kernels). Build any of them:
```
gcc <file>.c -I/usr/local/cuda/include -L/usr/local/cuda/lib64 -lnvrtc -lcuda -o <bin>
LD_LIBRARY_PATH=/usr/local/cuda/lib64 ./<bin> [args]
```

## The files
- **`nvrtc_smoke.c`** — NVRTC + `__shfl_sync` smoke test. Proves runtime-compile and
  warp-shuffle work on this box. `./nvrtc_smoke`
- **`cuda_coop.c`** — T=4 warp-cooperative ROMix (block split across 4 lanes, Salsa
  4×4 transpose via `__shfl_sync`, no `__local`/barriers). Byte-exact.
  `./cuda_coop <N>`. **Result: ~315 cand-equiv/s — NO-GO** (transpose compute tax >
  occupancy gain; even at 4× occupancy it loses).
- **`cuda_scalar.c`** — scalar uint4 ROMix, **K candidates interleaved per thread**
  (the cp.async / memory-level-parallelism thesis). Byte-exact.
  `./cuda_scalar <N> <K> <gap> <T> <TPB>`. **Result: monotonically WORSE with K
  (K=1=515 tuned, K=2=270, K=4=140) — NO-GO.** This is the experiment that proved the
  champion is **local-memory-bandwidth-bound, not global-latency-bound** (so cp.async,
  which targets global latency, would not help).
- **`cuda_shared.c`** — **THE CHOSEN KERNEL.** scalar uint4 ROMix with the working
  block `b` + `yo` scratch in dynamic `__shared__` (100 KB opt-in via
  `cuFuncSetAttribute`), `t` in local, TPB=64. Byte-exact.
  `./cuda_shared <N> <gap> <T> <TPB>` (T=0 → correctness run). **Result: ~560
  cand-equiv/s — the fastest measured, +8.6% over a tuned-local baseline (515),
  +6.7% over the OpenCL champion (525).**
- **`cuda_shared2.c`** — variant with `t` also in shared (all-shared). Byte-exact.
  **Result: WORSE (~424)** — forces TPB ≤ 39 = 1 warp/SM; occupancy loss dominates.
  Kept as the negative that pins the best config to b+yo-shared / t-local / TPB=64.

## Why none of this reaches 1 KH/s (the ceiling story)
scrypt(N=16384, r=8) mandates a **1 KB working block** that BlockMix must churn 2N
times per pass. It spills out of registers to local memory, and that local-memory /
LSU-transaction bandwidth is the **irreducible bind**. Three restructurings confirm it:
- champion uint4 (block in local, TMTO for occupancy) = **525** — the sweet spot;
- coop-T4 (block in registers, + transpose compute) = **315**;
- K-interleave (K× the local footprint) = **≤270**.
`__shared__` (`cuda_shared.c`) *shaves* the tax ~+9% (→ ~560) but does not remove the
wall. 1 KH/s would need ~2×; it is not reachable by kernel restructuring on this GPU.
The gap-3 TMTO optimum held across every variant.

## Decision (2026-08-22)
Bank the OpenCL champion (525) as the production artifact — portable, Arc-validated,
already integrated. A NVIDIA-only ~+9% does not justify building + maintaining a full
second backend. These harnesses are the documented positive/negative results and a
reserve lever if the trade-off ever changes.
