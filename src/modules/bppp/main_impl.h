/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BPPP_MAIN_IMPL_H
#define SECP256K1_MODULE_BPPP_MAIN_IMPL_H

#include "../../../include/secp256k1_bppp.h"
#include "../../../include/secp256k1_generator.h"
#include "../generator/main_impl.h" /* for generator_{load, save} */
#include "../../hash.h"
#include "../../util.h"
#include "../bppp/main.h"
#include "../bppp/bppp_norm_product_impl.h"

secp256k1_bppp_generators *secp256k1_bppp_generators_create(const secp256k1_context *ctx, size_t n) {
    secp256k1_bppp_generators *ret;
    secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char seed[64];
    size_t i;

    VERIFY_CHECK(ctx != NULL);

    /* Must have atleast 8 generators */
    if (n <= 8) {
        return NULL;
    }

    ret = (secp256k1_bppp_generators *)checked_malloc(&ctx->error_callback, sizeof(*ret));
    if (ret == NULL) {
        return NULL;
    }
    ret->gens = (secp256k1_ge*)checked_malloc(&ctx->error_callback, n * sizeof(*ret->gens));
    if (ret->gens == NULL) {
        free(ret);
        return NULL;
    }
    ret->n = n;

    secp256k1_fe_get_b32(&seed[0], &secp256k1_ge_const_g.x);
    secp256k1_fe_get_b32(&seed[32], &secp256k1_ge_const_g.y);

    secp256k1_rfc6979_hmac_sha256_initialize(&rng, seed, 64);
    for (i = 0; i < n; i++) {
        secp256k1_generator gen;
        unsigned char tmp[32] = { 0 };
        if (i == n - 8) {
            /* The first generator in H is secp G */
            ret->gens[i] = secp256k1_ge_const_g;
            continue;
        }
        secp256k1_rfc6979_hmac_sha256_generate(&rng, tmp, 32);
        CHECK(secp256k1_generator_generate(ctx, &gen, tmp));
        secp256k1_generator_load(&ret->gens[i], &gen);
    }

    return ret;
}

void secp256k1_bppp_generators_destroy(const secp256k1_context* ctx, secp256k1_bppp_generators *gens) {
    VERIFY_CHECK(ctx != NULL);
    (void) ctx;
    if (gens != NULL) {
        free(gens->gens);
        free(gens);
    }
}

size_t secp256k1_bulletproofs_pp_rangeproof_proof_length(
    const secp256k1_context* ctx,
    size_t n_bits,
    size_t base
) {
    size_t num_digits, n_rounds, g_len, h_len;
    VERIFY_CHECK(ctx != NULL);
    if (n_bits > 64 || base < 2 || base > 64) {
        return 0;
    }

    if (!secp256k1_is_power_of_two(base) || !secp256k1_is_power_of_two(n_bits)) {
        return 0;
    }
    num_digits = n_bits / secp256k1_bppp_log2(base);
    if (!secp256k1_is_power_of_two(num_digits)) {
        return 0;
    }
    g_len = num_digits > base ? num_digits : base;
    h_len = 8;
    n_rounds = secp256k1_bppp_log2(g_len > h_len ? g_len : h_len);
    return 33 * 4 + 65*n_rounds + 64;
}

#endif
