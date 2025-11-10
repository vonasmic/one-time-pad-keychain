#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "address.h"
#include "merkle.h"
#include "params.h"
#include "utils.h"
#include "utilsx1.h"
#include "wots.h"
#include "wotsx1.h"

// Debug output macro - use printf with fflush since we're in liboqs code
#define DBG_PRINTF(fmt, ...) do { printf(fmt, ##__VA_ARGS__); fflush(stdout); } while(0)

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path).  This is in this file because most of the complexity
 * is involved with the WOTS signature; the Merkle authentication path logic
 * is mostly hidden in treehashx4
 */
void merkle_sign(uint8_t *sig, unsigned char *root,
                 const spx_ctx *ctx,
                 uint32_t wots_addr[8], uint32_t tree_addr[8],
                 uint32_t idx_leaf) {
    DBG_PRINTF("DBG: [PQClean] merkle_sign() entered\r\n");
    
    unsigned char *auth_path = sig + SPX_WOTS_BYTES;
    struct leaf_info_x1 info = { 0 };
    unsigned steps[ SPX_WOTS_LEN ];

    DBG_PRINTF("DBG: [PQClean] merkle_sign: setting up info structure\r\n");
    info.wots_sig = sig;
    DBG_PRINTF("DBG: [PQClean] merkle_sign: calling chain_lengths()\r\n");
    chain_lengths(steps, root);
    info.wots_steps = steps;

    DBG_PRINTF("DBG: [PQClean] merkle_sign: setting address types\r\n");
    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    DBG_PRINTF("DBG: [PQClean] merkle_sign: calling treehashx1() (heavy computation)\r\n");
    treehashx1(root, auth_path, ctx,
               idx_leaf, 0,
               SPX_TREE_HEIGHT,
               wots_gen_leafx1,
               tree_addr, &info);
    DBG_PRINTF("DBG: [PQClean] merkle_sign: treehashx1() returned\r\n");
    DBG_PRINTF("DBG: [PQClean] merkle_sign() returning\r\n");
}

/* Compute root node of the top-most subtree. */
void merkle_gen_root(unsigned char *root, const spx_ctx *ctx) {
    DBG_PRINTF("DBG: [PQClean] merkle_gen_root() entered\r\n");
    
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    DBG_PRINTF("DBG: [PQClean] allocating auth_path (%lu bytes)\r\n", 
           (unsigned long)(SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES));
    unsigned char auth_path[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
    uint32_t top_tree_addr[8] = {0};
    DBG_PRINTF("DBG: [PQClean] auth_path allocated, calling treehashx1()\r\n");
    uint32_t wots_addr[8] = {0};

    DBG_PRINTF("DBG: [PQClean] setting layer addresses\r\n");
    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_layer_addr(wots_addr, SPX_D - 1);

    DBG_PRINTF("DBG: [PQClean] calling merkle_sign() (this is the complex operation)\r\n");
    merkle_sign(auth_path, root, ctx,
                wots_addr, top_tree_addr,
                ~0U /* ~0 means "don't bother generating an auth path */ );
    DBG_PRINTF("DBG: [PQClean] merkle_sign() returned\r\n");
    DBG_PRINTF("DBG: [PQClean] merkle_gen_root() returning\r\n");
}
