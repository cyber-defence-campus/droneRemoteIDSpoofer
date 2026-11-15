/* Raw C microbenchmark of libgroupsig operations used by CPBS (no Python).
 *
 * Usage: bench_groupsig <scheme: ps16|bbs04> <iters> <group sizes, comma separated>
 * Output (TSV on stdout): scheme, operation, group_size, n, median_us, p95_us, mean_us
 *
 * Build: see bench/build_bench.sh
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "groupsig.h"
#include "gml.h"
#include "message.h"
#include "ps16.h"
#include "bbs04.h"

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void report(const char *scheme, const char *op, int gsize, double *t, int n) {
    double mean = 0;
    for (int i = 0; i < n; i++) mean += t[i];
    qsort(t, n, sizeof(double), cmp);
    printf("%s\t%s\t%d\t%d\t%.1f\t%.1f\t%.1f\n", scheme, op, gsize, n,
           t[n / 2], t[(int)(0.95 * (n - 1))], mean / n);
}

/* Full join protocol, alternating manager/member steps. */
static groupsig_key_t *join(uint8_t code, groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml) {
    uint8_t start, seq;
    groupsig_get_joinstart(code, &start);
    groupsig_get_joinseq(code, &seq);
    groupsig_key_t *memkey = groupsig_mem_key_init(code);
    message_t *in = NULL;
    for (int step = start; step <= seq; step++) {
        message_t *out = NULL;
        int mgr = (step % 2 == 0) == (start == 0);
        int rc = mgr ? groupsig_join_mgr(&out, gml, mgrkey, step, in, grpkey)
                     : groupsig_join_mem(&out, memkey, step, in, grpkey);
        if (rc == IERROR) { fprintf(stderr, "join step %d failed\n", step); exit(1); }
        if (in) message_free(in);
        in = out;
    }
    if (in) message_free(in);
    return memkey;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s ps16|bbs04 iters sizes\n", argv[0]);
        return 2;
    }
    const char *name = argv[1];
    uint8_t code = !strcmp(name, "ps16") ? GROUPSIG_PS16_CODE : GROUPSIG_BBS04_CODE;
    int iters = atoi(argv[2]);
    double *t = malloc(sizeof(double) * iters);
    groupsig_init(code, 0);

    byte_t payload[300];  /* about the size of the signed Core prefix */
    memset(payload, 0xA5, sizeof(payload));
    message_t *msg = message_from_bytes(payload, sizeof(payload));

    char *sizes = strdup(argv[3]);
    for (char *tok = strtok(sizes, ","); tok; tok = strtok(NULL, ",")) {
        int gsize = atoi(tok);
        groupsig_key_t *grpkey = groupsig_grp_key_init(code), *mgrkey = groupsig_mgr_key_init(code);
        gml_t *gml = gml_init(code);

        double t0 = now_us();
        groupsig_setup(code, grpkey, mgrkey, gml);
        double setup = now_us() - t0;
        report(name, "setup", gsize, &setup, 1);

        /* Enrol the whole group (= cost of an epoch rollover); time each join. */
        double *tj = malloc(sizeof(double) * gsize);
        groupsig_key_t *memkey = NULL;
        for (int i = 0; i < gsize; i++) {
            t0 = now_us();
            groupsig_key_t *k = join(code, grpkey, mgrkey, gml);
            tj[i] = now_us() - t0;
            if (memkey) groupsig_mem_key_free(memkey);
            memkey = k;  /* keep the last member: worst case for a linear-scan open */
        }
        report(name, "join", gsize, tj, gsize);
        free(tj);

        groupsig_signature_t *sig = groupsig_signature_init(code);
        for (int i = 0; i < iters; i++) {
            groupsig_signature_t *s = groupsig_signature_init(code);
            t0 = now_us();
            groupsig_sign(s, msg, memkey, grpkey, 0);
            t[i] = now_us() - t0;
            groupsig_signature_free(s);
        }
        report(name, "sign", gsize, t, iters);
        groupsig_sign(sig, msg, memkey, grpkey, 0);

        uint8_t ok = 0;
        for (int i = 0; i < iters; i++) {
            t0 = now_us();
            groupsig_verify(&ok, sig, msg, grpkey);
            t[i] = now_us() - t0;
        }
        if (!ok) { fprintf(stderr, "verify failed\n"); return 1; }
        report(name, "verify", gsize, t, iters);

        int open_iters = iters < 20 ? iters : 20;
        uint64_t index = 0;
        for (int i = 0; i < open_iters; i++) {
            groupsig_proof_t *proof = groupsig_proof_init(code);
            t0 = now_us();
            groupsig_open(&index, proof, NULL, sig, grpkey, mgrkey, gml);
            t[i] = now_us() - t0;
            groupsig_proof_free(proof);
        }
        if (index != (uint64_t)(gsize - 1)) { fprintf(stderr, "open returned %lu\n", index); return 1; }
        report(name, "open", gsize, t, open_iters);

        groupsig_signature_free(sig);
        groupsig_mem_key_free(memkey);
        groupsig_grp_key_free(grpkey);
        groupsig_mgr_key_free(mgrkey);
        gml_free(gml);
    }
    message_free(msg);
    groupsig_clear(code);
    return 0;
}
