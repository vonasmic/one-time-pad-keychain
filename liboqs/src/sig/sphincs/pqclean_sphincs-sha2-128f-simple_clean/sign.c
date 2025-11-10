#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "address.h"
#include "context.h"
#include "fors.h"
#include "hash.h"
#include "merkle.h"
#include "nistapi.h"
#include "params.h"
#include "randombytes.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"

// Debug output macro - use printf with fflush since we're in liboqs code
#define DBG_PRINTF(fmt, ...) do { printf(fmt, ##__VA_ARGS__); fflush(stdout); } while(0)

/*
 * Returns the length of a secret key, in bytes
 */
size_t crypto_sign_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

/*
 * Returns the length of a public key, in bytes
 */
size_t crypto_sign_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

/*
 * Returns the length of a signature, in bytes
 */
size_t crypto_sign_bytes(void) {
    return CRYPTO_BYTES;
}

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
size_t crypto_sign_seedbytes(void) {
    return CRYPTO_SEEDBYTES;
}

/*
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_seed_keypair(uint8_t *pk, uint8_t *sk,
                             const uint8_t *seed) {
    DBG_PRINTF("DBG: [PQClean] crypto_sign_seed_keypair() entered\r\n");
    
    spx_ctx ctx;
    DBG_PRINTF("DBG: [PQClean] ctx allocated\r\n");

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    DBG_PRINTF("DBG: [PQClean] memcpy seed to sk\r\n");
    memcpy(sk, seed, CRYPTO_SEEDBYTES);
    DBG_PRINTF("DBG: [PQClean] memcpy pk\r\n");
    memcpy(pk, sk + 2 * SPX_N, SPX_N);
    DBG_PRINTF("DBG: [PQClean] memcpy ctx seeds\r\n");
    memcpy(ctx.pub_seed, pk, SPX_N);
    memcpy(ctx.sk_seed, sk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    DBG_PRINTF("DBG: [PQClean] calling initialize_hash_function()\r\n");
    initialize_hash_function(&ctx);
    DBG_PRINTF("DBG: [PQClean] initialize_hash_function() returned\r\n");

    /* Compute root node of the top-most subtree. */
    DBG_PRINTF("DBG: [PQClean] calling merkle_gen_root()\r\n");
    merkle_gen_root(sk + 3 * SPX_N, &ctx);
    DBG_PRINTF("DBG: [PQClean] merkle_gen_root() returned\r\n");

    // cleanup
    DBG_PRINTF("DBG: [PQClean] calling free_hash_function()\r\n");
    free_hash_function(&ctx);
    DBG_PRINTF("DBG: [PQClean] free_hash_function() returned\r\n");

    DBG_PRINTF("DBG: [PQClean] final memcpy\r\n");
    memcpy(pk + SPX_N, sk + 3 * SPX_N, SPX_N);

    DBG_PRINTF("DBG: [PQClean] crypto_sign_seed_keypair() returning 0\r\n");
    return 0;
}

/*
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    // Force memory write to ensure function entry is reached
    volatile static uint32_t entry_marker = 0;
    entry_marker = 0xCAFEBABE;
    
    // Try immediate output before any stack allocation
    DBG_PRINTF("DBG: [PQClean] crypto_sign_keypair() entered, pk=%p sk=%p\r\n", pk, sk);
    
    uint8_t seed[CRYPTO_SEEDBYTES];
    DBG_PRINTF("DBG: [PQClean] calling randombytes() for seed\r\n");
    randombytes(seed, CRYPTO_SEEDBYTES);
    DBG_PRINTF("DBG: [PQClean] randombytes() returned\r\n");
    
    DBG_PRINTF("DBG: [PQClean] calling crypto_sign_seed_keypair()\r\n");
    crypto_sign_seed_keypair(pk, sk, seed);
    DBG_PRINTF("DBG: [PQClean] crypto_sign_seed_keypair() returned\r\n");

    DBG_PRINTF("DBG: [PQClean] crypto_sign_keypair() returning 0\r\n");
    return 0;
}

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk) {
    spx_ctx ctx;

    const uint8_t *sk_prf = sk + SPX_N;
    const uint8_t *pk = sk + 2 * SPX_N;

    uint8_t optrand[SPX_N];
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t root[SPX_N];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes(optrand, SPX_N);
    /* Compute the digest randomization value. */
    gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    free_hash_function(&ctx);

    *siglen = SPX_BYTES;

    return 0;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk) {
    spx_ctx ctx;
    const uint8_t *pub_root = pk + SPX_N;
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t wots_pk[SPX_WOTS_BYTES];
    uint8_t root[SPX_N];
    uint8_t leaf[SPX_N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != SPX_BYTES) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    // cleanup
    free_hash_function(&ctx);

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N) != 0) {
        return -1;
    }

    return 0;
}

/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk) {
    size_t siglen;

    crypto_sign_signature(sm, &siglen, m, mlen, sk);

    memmove(sm + SPX_BYTES, m, mlen);
    *smlen = siglen + mlen;

    return 0;
}

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk) {
    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly SPX_BYTES. */
    if (smlen < SPX_BYTES) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    *mlen = smlen - SPX_BYTES;

    if (crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, *mlen, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    /* If verification was successful, move the message to the right place. */
    memmove(m, sm + SPX_BYTES, *mlen);

    return 0;
}
