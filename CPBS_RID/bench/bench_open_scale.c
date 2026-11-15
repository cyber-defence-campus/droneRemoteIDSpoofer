/* Scaling benchmark for BBS04 opening at large group sizes (libgroupsig).
 *
 * libgroupsig's bbs04_open recovers the signer's A = T3 / (T1^xi1 * T2^xi2) and then
 * resolves A by a linear scan of the GML, so opening grows linearly with the group size.
 * This benchmark compares that against an indexed GML: the opener keeps a hash table
 * from the compressed encoding of each member's A to its GML entry. Only the opener can
 * recover A from a signature (it needs xi1, xi2), so the index changes the cost of the
 * lookup, not who can open; it holds the same A values as the GML itself.
 *
 * Usage: bench_open_scale <iters> <group sizes, comma separated> [synthetic|real]
 *
 *   synthetic (default): the GML is filled with n-1 distinct synthetic G1 points
 *       (A_i = A_{i-1} + B), stored exactly like real entries (bbs04 GML entries holding
 *       a heap-allocated G1 element), and one real member is then joined last, so it
 *       sits at index n-1 (worst case for the scan). This makes 10^6..10^7 members
 *       feasible; a full join costs ~0.7 ms (x86) / ~6.7 ms (RPi 4) per member.
 *   real: all n members go through the full join protocol (used to calibrate the
 *       synthetic fill at small n).
 *
 * Output (TSV on stdout): scheme, operation, group_size, n, median_us, p95_us, mean_us
 *   gml_fill_*      : one row, total time in microseconds
 *   rss_B_per_entry : one row, resident memory per GML entry in bytes
 *   open_scan       : groupsig_open (linear scan), worst case
 *   index_build     : one row, total time to index the whole GML in microseconds
 *   open_indexed    : recover A + serialize + hash lookup + confirm against the GML entry
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "groupsig.h"
#include "gml.h"
#include "message.h"
#include "bbs04.h"
#include "shim/pbc_ext.h"
#include "groupsig/bbs04/gml.h"
#include "groupsig/bbs04/signature.h"
#include "groupsig/bbs04/mgr_key.h"

#define G1_BYTES 48  /* compressed BLS12-381 G1 */

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void report(const char *op, long gsize, double *t, int n) {
    double mean = 0;
    for (int i = 0; i < n; i++) mean += t[i];
    qsort(t, n, sizeof(double), cmp);
    printf("bbs04\t%s\t%ld\t%d\t%.1f\t%.1f\t%.1f\n", op, gsize, n,
           t[n / 2], t[(int)(0.95 * (n - 1))], mean / n);
    fflush(stdout);
}

static long rss_bytes(void) {
    FILE *f = fopen("/proc/self/statm", "r");
    long pages = 0, rss = 0;
    if (f) { if (fscanf(f, "%ld %ld", &pages, &rss) != 2) rss = 0; fclose(f); }
    return rss * 4096L;
}

static groupsig_key_t *join(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml) {
    uint8_t code = GROUPSIG_BBS04_CODE, start, seq;
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

/* ---- Indexed GML: open addressing, 64-bit fingerprint of the compressed A -> GML index.
 * A fingerprint hit is confirmed with a full G1 comparison against the GML entry, as a
 * database-backed authority would confirm a row. 16 B per slot, load factor <= 0.5. */
typedef struct { uint64_t fp; uint64_t idx1; } slot_t;  /* idx1 = index + 1, 0 = empty */
typedef struct { slot_t *s; uint64_t mask; } index_t;

static uint64_t fingerprint(const unsigned char *b) {
    uint64_t x;  /* bytes 8..15 of the x-coordinate: uniform, no flag bits */
    memcpy(&x, b + 8, 8);
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33;
    return x;
}

static void index_init(index_t *ix, uint64_t n) {
    uint64_t cap = 1;
    while (cap < 2 * n) cap <<= 1;
    ix->s = calloc(cap, sizeof(slot_t));
    if (!ix->s) { fprintf(stderr, "index alloc failed\n"); exit(1); }
    ix->mask = cap - 1;
}

static void index_put(index_t *ix, const unsigned char *b, uint64_t idx) {
    uint64_t fp = fingerprint(b), i = fp & ix->mask;
    while (ix->s[i].idx1) i = (i + 1) & ix->mask;
    ix->s[i].fp = fp;
    ix->s[i].idx1 = idx + 1;
}

static int64_t index_get(index_t *ix, gml_t *gml, const unsigned char *b, pbcext_element_G1_t *A) {
    uint64_t fp = fingerprint(b), i = fp & ix->mask;
    for (; ix->s[i].idx1; i = (i + 1) & ix->mask) {
        if (ix->s[i].fp != fp) continue;
        gml_entry_t *e = gml->entries[ix->s[i].idx1 - 1];
        if (!pbcext_element_G1_cmp(e->data, A)) return (int64_t)e->id;
    }
    return -1;
}

/* bbs04_open's recovery step, then an index lookup instead of the linear scan. */
static int64_t open_indexed(index_t *ix, gml_t *gml, groupsig_signature_t *sig, groupsig_key_t *mgrkey) {
    bbs04_signature_t *s = sig->sig;
    bbs04_mgr_key_t *mk = mgrkey->key;
    pbcext_element_G1_t A, aux;
    unsigned char b[G1_BYTES];
    pbcext_element_G1_mul(&A, s->T1, mk->xi1);
    pbcext_element_G1_mul(&aux, s->T2, mk->xi2);
    pbcext_element_G1_add(&A, &A, &aux);
    pbcext_element_G1_sub(&A, s->T3, &A);
    if (mclBnG1_serialize(b, sizeof b, &A) != G1_BYTES) return -1;
    return index_get(ix, gml, b, &A);
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "usage: %s iters sizes [synthetic|real]\n", argv[0]);
        return 2;
    }
    int iters = atoi(argv[1]);
    int real = argc == 4 && !strcmp(argv[3], "real");
    uint8_t code = GROUPSIG_BBS04_CODE;
    double *t = malloc(sizeof(double) * iters);
    groupsig_init(code, 0);

    byte_t payload[300];
    memset(payload, 0xA5, sizeof(payload));
    message_t *msg = message_from_bytes(payload, sizeof(payload));
    const char *fill_op = real ? "gml_fill_real" : "gml_fill_synthetic";

    char *sizes = strdup(argv[2]);
    for (char *tok = strtok(sizes, ","); tok; tok = strtok(NULL, ",")) {
        long gsize = atol(tok);
        groupsig_key_t *grpkey = groupsig_grp_key_init(code), *mgrkey = groupsig_mgr_key_init(code);
        gml_t *gml = gml_init(code);
        groupsig_setup(code, grpkey, mgrkey, gml);
        long rss0 = rss_bytes();

        /* Fill entries 0..n-2, then join one real member at index n-1. */
        double t0 = now_us();
        groupsig_key_t *memkey = NULL;
        if (real) {
            for (long i = 0; i < gsize; i++) {
                groupsig_key_t *k = join(grpkey, mgrkey, gml);
                if (memkey) groupsig_mem_key_free(memkey);
                memkey = k;
            }
        } else {
            /* Pre-size the entry array (bbs04_gml_insert reallocs by one per insert). */
            gml->entries = realloc(gml->entries, sizeof(gml_entry_t *) * gsize);
            pbcext_element_G1_t A, B;
            pbcext_element_G1_random(&A);
            pbcext_element_G1_random(&B);
            for (long i = 0; i < gsize - 1; i++) {
                gml_entry_t *e = bbs04_gml_entry_init();
                e->data = pbcext_element_G1_init();
                /* Real entries are normalized (Z = 1): join_mgr stores A via G1_set, which
                 * round-trips through serialization. Normalize directly; that round trip
                 * decompresses the point and would dominate the fill time. */
                mclBnG1_normalize(e->data, &A);
                e->id = i;
                gml->entries[i] = e;
                pbcext_element_G1_add(&A, &A, &B);
            }
            gml->n = gsize - 1;
            memkey = join(grpkey, mgrkey, gml);
        }
        double fill = now_us() - t0;
        report(fill_op, gsize, &fill, 1);
        double per_entry = (double)(rss_bytes() - rss0) / gsize;
        report("rss_B_per_entry", gsize, &per_entry, 1);

        groupsig_signature_t *sig = groupsig_signature_init(code);
        groupsig_sign(sig, msg, memkey, grpkey, 0);

        /* Linear scan (libgroupsig). Fewer iterations at large n: each costs O(n). */
        int scan_iters = gsize >= 1000000 ? 5 : (iters < 20 ? iters : 20);
        uint64_t index = 0;
        for (int i = 0; i < scan_iters; i++) {
            groupsig_proof_t *proof = groupsig_proof_init(code);
            t0 = now_us();
            groupsig_open(&index, proof, NULL, sig, grpkey, mgrkey, gml);
            t[i] = now_us() - t0;
            groupsig_proof_free(proof);
        }
        if (index != (uint64_t)(gsize - 1)) { fprintf(stderr, "open returned %lu\n", index); return 1; }
        report("open_scan", gsize, t, scan_iters);

        /* Indexed GML (built once per epoch, e.g. as members join). */
        index_t ix;
        index_init(&ix, gml->n);
        unsigned char b[G1_BYTES];
        t0 = now_us();
        for (uint64_t i = 0; i < gml->n; i++) {
            if (mclBnG1_serialize(b, sizeof b, gml->entries[i]->data) != G1_BYTES) {
                fprintf(stderr, "serialize failed\n"); return 1;
            }
            index_put(&ix, b, i);
        }
        double build = now_us() - t0;
        report("index_build", gsize, &build, 1);

        for (int i = 0; i < iters; i++) {
            t0 = now_us();
            int64_t id = open_indexed(&ix, gml, sig, mgrkey);
            t[i] = now_us() - t0;
            if (id != gsize - 1) { fprintf(stderr, "indexed open returned %ld\n", (long)id); return 1; }
        }
        report("open_indexed", gsize, t, iters);
        free(ix.s);

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
