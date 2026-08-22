/* rxe38 CUDA backend #2 -- end-to-end crack path (included into rxe38.c after
 * crack_gpu, so it reuses bip38_finish, address_matches, pbkdf2, etc.).
 *
 * Hybrid per batch: (1) host pbkdf2_first -> B, scattered lane-interleaved
 * (threaded); (2) GPU ROMix over the p blocks (scrypt_romix_cuda); (3) host
 * pbkdf2_final -> dk then AES/secp/address-verify (threaded), lowest-GLOBAL-
 * index-wins hit recording.
 *
 * DOUBLE-BUFFERED like the OpenCL path: two slots. A filled slot runs pbkdf1
 * (host) -> upload -> GPU ROMix -> download (blocking on the GPU), then SPAWNS
 * its verify ASYNC and moves on to fill+process the next slot -- so batch N's
 * verify (CPU secp256k1) overlaps batch N+1's GPU ROMix. A slot's verify is
 * joined before its buffers are reused; both slots joined at end. The recorded
 * hit is the LOWEST GLOBAL INDEX match (mpz), order-independent. Layout is
 * byte-identical to scrypt_romix_only: word w of block pblk, cand l lives at
 * bwork[(pblk*W+w)*count + l] and the kernel is launched with NL=count.
 * RXE38_GPU_DBLBUF=0 forces the serial path (join each slot immediately). */

#define CU2(x) do{ CUresult _r=(x); if(_r!=CUDA_SUCCESS){ const char*_s=0; cuGetErrorString(_r,&_s); \
    fprintf(stderr,"rxe38 cuda: CU %s:%d: %s\n",__FILE__,__LINE__,_s?_s:"?"); return -1; } }while(0)

struct cuda_slot {
    unsigned char *pwbuf;        /* cap * GPU_MAXPW */
    cl_uint  *lens;
    mpz_t    *idxs;
    uint32_t *bwork;             /* cap * PP * W  (host, lane-interleaved) */
    size_t    count;             /* filled this batch */
    pthread_t tid[64];
    struct cjob *jobs;           /* [64] */
    int       nspawn, busy;
};

struct cuda_crack {
    const struct bip38 *key;
    cl_uint   N, gap, PP, W;      /* W = 256 words/block */
    size_t    cap;               /* candidates/batch */
    struct cuda_slot slot[2];
    int       cur, dblbuf;
    unsigned long tried, toolong;
    int       found, hitset, vthreads;
    pthread_mutex_t vmtx;
    char      pass[512], wif[64];
    mpz_t     hitidx;
    CUdeviceptr dB, dV;
    CUfunction  romix;
    cl_uint     tpb;
    double    t_gpu, t_host;
};

struct cjob { struct cuda_crack *c; struct cuda_slot *s; size_t lo, hi; };

/* pbkdf2_first for lanes [lo,hi) of slot s: scatter each candidate's p blocks
 * into s->bwork lane-interleaved (stride = s->count, matching the kernel's NL). */
static void *cuda_pbkdf1_worker(void *arg)
{
    struct cjob *j = arg; struct cuda_crack *c = j->c; struct cuda_slot *s = j->s;
    size_t blocklen = 128 * (size_t)GPU_R;               /* 1024 bytes */
    unsigned char *B = malloc(blocklen * c->PP);
    for (size_t l = j->lo; l < j->hi; l++) {
        pbkdf2_hmac_sha256_c1(s->pwbuf + l*GPU_MAXPW, s->lens[l],
                              c->key->addrhash, 4, B, blocklen * c->PP);
        const uint32_t *Bw = (const uint32_t *)B;        /* PP*W words */
        for (cl_uint pblk = 0; pblk < c->PP; pblk++)
            for (cl_uint w = 0; w < c->W; w++)
                s->bwork[((size_t)(pblk*c->W + w))*s->count + l] = Bw[pblk*c->W + w];
    }
    free(B);
    return NULL;
}

/* Gather ROMix'd B back, pbkdf2_final -> dk, finish+verify, record lowest-index. */
static void *cuda_verify_worker(void *arg)
{
    struct cjob *j = arg; struct cuda_crack *c = j->c; struct cuda_slot *s = j->s;
    size_t blocklen = 128 * (size_t)GPU_R;
    unsigned char *B = malloc(blocklen * c->PP);
    unsigned char dk[64], priv[32];
    uint32_t *Bw = (uint32_t *)B;
    for (size_t l = j->lo; l < j->hi; l++) {
        for (cl_uint pblk = 0; pblk < c->PP; pblk++)
            for (cl_uint w = 0; w < c->W; w++)
                Bw[pblk*c->W + w] = s->bwork[((size_t)(pblk*c->W + w))*s->count + l];
        pbkdf2_hmac_sha256_c1(s->pwbuf + l*GPU_MAXPW, s->lens[l], B, blocklen * c->PP, dk, 64);
        bip38_finish(c->key, dk, priv);
        if (address_matches(priv, c->key->compressed, c->key->addrhash)) {
            pthread_mutex_lock(&c->vmtx);
            if (!c->hitset || mpz_cmp(s->idxs[l], c->hitidx) < 0) {
                c->hitset = 1; c->found = 1;
                size_t n = s->lens[l] < sizeof c->pass - 1 ? s->lens[l] : sizeof c->pass - 1;
                memcpy(c->pass, s->pwbuf + l*GPU_MAXPW, n); c->pass[n] = '\0';
                privkey_to_wif(priv, c->key->compressed, c->wif);
                mpz_set(c->hitidx, s->idxs[l]);
            }
            pthread_mutex_unlock(&c->vmtx);
        }
    }
    free(B);
    return NULL;
}

/* Fan a host phase across vthreads workers on slot s. Blocking unless async
 * (verify with dblbuf): async leaves the threads running in s->tid to join later.*/
static void cuda_fan(struct cuda_crack *c, struct cuda_slot *s,
                     void *(*fn)(void *), int async)
{
    int T = c->vthreads;
    if (T > (int)s->count) T = (int)s->count ? (int)s->count : 1;
    if (T > 64) T = 64;
    size_t per = (s->count + T - 1) / T;
    int spun = 0;
    for (int t = 0; t < T; t++) {
        size_t lo = (size_t)t*per, hi = lo+per;
        if (lo >= s->count) break;
        if (hi > s->count) hi = s->count;
        s->jobs[spun] = (struct cjob){ c, s, lo, hi };
        if (pthread_create(&s->tid[spun], NULL, fn, &s->jobs[spun]) == 0) spun++;
        else fn(&s->jobs[spun]);
    }
    s->nspawn = spun;
    if (async) { s->busy = 1; return; }
    for (int t = 0; t < spun; t++) pthread_join(s->tid[t], NULL);
    s->nspawn = 0;
}

static void cuda_slot_join(struct cuda_slot *s)
{
    if (!s->busy) return;
    for (int t = 0; t < s->nspawn; t++) pthread_join(s->tid[t], NULL);
    s->nspawn = 0; s->busy = 0;
}

/* Run one filled slot: host pbkdf1 -> GPU ROMix -> spawn host verify (async in
 * dblbuf mode). Returns 1 if a hit is recorded so far. */
static int cuda_flush_slot(struct cuda_crack *c, struct cuda_slot *s)
{
    if (s->count == 0) return c->found;
    double th = now_sec();
    cuda_fan(c, s, cuda_pbkdf1_worker, 0);               /* pbkdf2_first (blocking) */
    c->t_host += now_sec() - th;

    double tg = now_sec();
    size_t iow = s->count * c->PP * c->W;
    CU2(cuMemcpyHtoD(c->dB, s->bwork, iow*4));
    cl_uint uN=c->N, ug=c->gap, unl=(cl_uint)s->count, upp=c->PP;
    void *args[] = { &c->dB, &c->dV, &uN, &ug, &unl, &upp };
    unsigned grid = ((unsigned)s->count + c->tpb - 1) / c->tpb;
    CU2(cuLaunchKernel(c->romix, grid,1,1, c->tpb,1,1, 0,0, args, 0));
    CU2(cuCtxSynchronize());
    CU2(cuMemcpyDtoH(s->bwork, c->dB, iow*4));
    c->t_gpu += now_sec() - tg;

    cuda_fan(c, s, cuda_verify_worker, c->dblbuf);       /* pbkdf2_final + verify */
    if (!c->dblbuf) {
        th = now_sec();
        cuda_slot_join(s);
        c->t_host += now_sec() - th;
    }
    c->tried += s->count;
    return c->found;
}

static int cuda_sink(const char *str, size_t len, const mpz_t index, void *v)
{
    struct cuda_crack *c = v;
    if (c->found) return 1;
    if (len > GPU_MAXPW) { c->toolong++; return 0; }
    struct cuda_slot *s = &c->slot[c->cur];
    size_t l = s->count;
    memcpy(s->pwbuf + l*GPU_MAXPW, str, len);
    s->lens[l] = (cl_uint)len;
    mpz_set(s->idxs[l], index);
    s->count++;
    if (s->count == c->cap) {
        int found = cuda_flush_slot(c, s);               /* GPU + spawn verify */
        c->cur ^= 1;
        struct cuda_slot *ns = &c->slot[c->cur];
        double tj = now_sec();
        cuda_slot_join(ns);                              /* free it before reuse */
        c->t_host += now_sec() - tj;
        ns->count = 0;
        return found || c->found;
    }
    return 0;
}

/* --backend cuda crack entry point. */
static int crack_gpu_cuda(const struct bip38 *key, const char *pattern,
                          size_t batch, cl_uint N, int progress, long count)
{
    (void)progress;
    struct rxe *rxe = rxe_parse(pattern, 0);
    if (!rxe || rxe_error(rxe)) {
        fprintf(stderr, "rxe38: bad passphrase regex: %s\n",
                rxe ? rxe_error_message(rxe) : "parse failed");
        if (rxe) rxe_free(rxe);
        return 2;
    }

    struct cuda_gpu cg;
    if (cuda_setup(&cg) != 0) { rxe_free(rxe); return 1; }

    struct cuda_crack c;
    memset(&c, 0, sizeof c);
    c.key = key; c.N = N; c.PP = GPU_P; c.W = GPU_BLK / 4; c.romix = cg.romix;
    const char *gs = getenv("RXE38_GPU_GAP");
    c.gap = gs ? (cl_uint)strtoul(gs, 0, 0) : 1; if (c.gap < 1) c.gap = 1;
    c.tpb = 32;
    if (getenv("RXE38_CUDA_TPB")) c.tpb = (cl_uint)strtoul(getenv("RXE38_CUDA_TPB"), 0, 0);
    const char *db = getenv("RXE38_GPU_DBLBUF");
    c.dblbuf = db ? atoi(db) != 0 : 1;
    cl_uint vslots = (N + c.gap - 1) / c.gap;

    size_t freeb = 0, totalb = 0; cuMemGetInfo(&freeb, &totalb);
    size_t perlane_dev = (size_t)vslots * (c.W/4) * 16       /* dV per candidate */
                       + (size_t)c.PP * c.W * 4;             /* dB per candidate */
    if (batch > 0) c.cap = batch;
    else {
        const char *vf = getenv("RXE38_GPU_VRAM_FRAC");
        double frac = vf ? atof(vf) : 0.85; if (frac<=0||frac>=1) frac = 0.85;
        c.cap = (size_t)((double)totalb * frac / perlane_dev);
    }
    c.cap -= c.cap % c.tpb; if (c.cap < c.tpb) c.cap = c.tpb;

    fprintf(stderr, "rxe38 cuda: device=%s (sm_%d%d), batch=%zu lanes, N=%u gap=%u TPB=%u dblbuf=%d\n",
            cg.devname, cg.cc_major, cg.cc_minor, c.cap, N, c.gap, c.tpb, c.dblbuf);

    for (int sl = 0; sl < 2; sl++) {
        struct cuda_slot *s = &c.slot[sl];
        s->pwbuf = calloc(c.cap, GPU_MAXPW);
        s->lens  = calloc(c.cap, sizeof *s->lens);
        s->idxs  = calloc(c.cap, sizeof *s->idxs);
        s->bwork = calloc(c.cap * c.PP * c.W, sizeof *s->bwork);
        s->jobs  = calloc(64, sizeof *s->jobs);
        for (size_t i = 0; i < c.cap; i++) mpz_init(s->idxs[i]);
    }
    mpz_init(c.hitidx);
    pthread_mutex_init(&c.vmtx, NULL);
    if (cuMemAlloc(&c.dB, (size_t)c.cap * c.PP * c.W * 4) != CUDA_SUCCESS ||
        cuMemAlloc(&c.dV, (size_t)c.cap * vslots * (c.W/4) * 16) != CUDA_SUCCESS) {
        fprintf(stderr, "rxe38 cuda: device alloc failed (batch too big?)\n");
        return 1;
    }

    const char *vt = getenv("RXE38_VERIFY_THREADS");
    int usable = 0;
#ifdef CPU_COUNT
    cpu_set_t aff;
    if (sched_getaffinity(0, sizeof aff, &aff) == 0) usable = CPU_COUNT(&aff);
#endif
    if (usable <= 0) { long n = sysconf(_SC_NPROCESSORS_ONLN); usable = n>0?(int)n:1; }
    c.vthreads = vt ? atoi(vt) : (usable < 16 ? usable : 16);
    if (c.vthreads < 1) c.vthreads = 1;
    secp_init();
    fprintf(stderr, "rxe38 cuda: host pbkdf2/verify = %d thread(s)\n", c.vthreads);

    double t0 = now_sec();
    mpz_t from, cnt; mpz_init_set_ui(from, 0);
    mpz_init_set_ui(cnt, count > 0 ? (unsigned long)count : 0);
    rxe_foreach(rxe, from, cnt, GPU_MAXPW + 1, cuda_sink, &c);
    if (!c.found) cuda_flush_slot(&c, &c.slot[c.cur]);   /* trailing partial */
    cuda_slot_join(&c.slot[0]); cuda_slot_join(&c.slot[1]);
    double dt = now_sec() - t0;
    mpz_clear(from); mpz_clear(cnt);

    int rc;
    if (c.found) {
        printf("FOUND passphrase: %s\n", c.pass);
        printf("WIF: %s\n", c.wif);
        gmp_printf("index: %Zd   (%lu tried, %.1fs, %.1f cand/s)\n",
                   c.hitidx, c.tried, dt, dt > 0 ? c.tried/dt : 0);
        rc = 0;
    } else {
        fprintf(stderr, "rxe38: not found (%lu tried, %.1fs wall, %.1fs gpu, %.1fs host, "
                "%.1f cand/s)\n", c.tried, dt, c.t_gpu, c.t_host, dt>0?c.tried/dt:0);
        rc = 1;
    }
    if (c.toolong)
        fprintf(stderr, "rxe38 cuda: skipped %lu candidate(s) longer than %d bytes\n",
                c.toolong, GPU_MAXPW);

    for (int sl = 0; sl < 2; sl++) {
        struct cuda_slot *s = &c.slot[sl];
        for (size_t i = 0; i < c.cap; i++) mpz_clear(s->idxs[i]);
        free(s->pwbuf); free(s->lens); free(s->idxs); free(s->bwork); free(s->jobs);
    }
    mpz_clear(c.hitidx); pthread_mutex_destroy(&c.vmtx);
    cuMemFree(c.dB); cuMemFree(c.dV);
    cuda_teardown(&cg);
    rxe_free(rxe);
    return rc;
}
