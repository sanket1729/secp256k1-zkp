/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdint.h>

#include "include/secp256k1.h"
#include "include/secp256k1_bppp.h"
#include "util.h"
#include "bench.h"

#define MAX_PROOF_SIZE 2000
#define MAX_AGG_PROOFS 64
typedef struct {
    secp256k1_context* ctx;
    secp256k1_bppp_generators* gens;
    secp256k1_scratch_space *scratch;
    secp256k1_pedersen_commitment commit[MAX_AGG_PROOFS];
    unsigned char *proofs;
    unsigned char blind[32 * MAX_AGG_PROOFS];
    unsigned char nonce[32];
    size_t proof_len;
    size_t n_bits;
    size_t base;
    size_t num_proofs;
    uint64_t min_value[MAX_AGG_PROOFS];
    uint64_t value[MAX_AGG_PROOFS];
} bench_bppp_data;

static void bench_bppp_setup(void* arg) {
    bench_bppp_data *data = (bench_bppp_data*)arg;
    size_t i;
    data->proof_len = MAX_PROOF_SIZE;
    memset(data->nonce, 0x0, 32);
    for (i = 0; i < data->num_proofs; i++) {
        data->min_value[i] = 0;
        data->value[i] = 10;
        memset(&data->blind[32*i], 0x77, 32);
        CHECK(secp256k1_pedersen_commit(data->ctx, &data->commit[i], &data->blind[32*i], data->value[i], secp256k1_generator_h));
    }

    CHECK(secp256k1_bppp_rangeproof_agg_prove(data->ctx, data->scratch, data->gens, secp256k1_generator_h, data->proofs, &data->proof_len, data->n_bits, data->base, data->num_proofs, data->value, data->min_value, &data->commit[0], data->blind, data->nonce, NULL, 0));
    CHECK(secp256k1_bppp_rangeproof_agg_verify(data->ctx, data->scratch, data->gens, secp256k1_generator_h, data->proofs, data->proof_len, data->n_bits, data->base, data->num_proofs, data->min_value, &data->commit[0], NULL, 0));
}

static void bench_bppp_prove(void* arg, int iters) {
    bench_bppp_data *data = (bench_bppp_data*)arg;
    int i;

    for (i = 0; i < iters; i++) {
        data->nonce[1] = i;
        data->nonce[2] = i >> 8;
        data->nonce[3] = i >> 16;
        data->proof_len = MAX_PROOF_SIZE;
        CHECK(secp256k1_bppp_rangeproof_agg_prove(data->ctx, data->scratch, data->gens, secp256k1_generator_h, &data->proofs[i*MAX_PROOF_SIZE], &data->proof_len, data->n_bits, data->base, data->num_proofs, data->value, data->min_value, &data->commit[0], data->blind, data->nonce, NULL, 0));
    }
}

static void bench_bppp_verify(void* arg, int iters) {
    bench_bppp_data *data = (bench_bppp_data*)arg;
    int i;

    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_bppp_rangeproof_agg_verify(data->ctx, data->scratch, data->gens, secp256k1_generator_h, &data->proofs[i*MAX_PROOF_SIZE], data->proof_len, data->n_bits, data->base, data->num_proofs, data->min_value, &data->commit[0], NULL, 0));
    }
}

int main(void) {
    bench_bppp_data data;
    int iters = get_iters(64);
    char test_name[64];

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    data.scratch = secp256k1_scratch_space_create(data.ctx, 80 * 1024);
    data.proofs = (unsigned char *)malloc(iters * MAX_PROOF_SIZE);
    data.num_proofs = 2;
    data.gens = secp256k1_bppp_generators_create(data.ctx, 16 * data.num_proofs + 8);
    data.n_bits = 1ul << 6;
    data.base = 16;
    sprintf(test_name, "bppp_prove_64bits_16base");
    run_benchmark(test_name, bench_bppp_prove, bench_bppp_setup, NULL, &data, 4, iters);

    sprintf(test_name, "bppp_verify_64bits_16base");
    run_benchmark(test_name, bench_bppp_verify, bench_bppp_setup, NULL, &data, 20, iters);

    secp256k1_scratch_space_destroy(data.ctx, data.scratch);
    free(data.proofs);
    secp256k1_bppp_generators_destroy(data.ctx, data.gens);
    secp256k1_context_destroy(data.ctx);

    return 0;
}
