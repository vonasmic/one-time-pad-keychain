#ifndef OQS_SHIMS_SHA2_H
#define OQS_SHIMS_SHA2_H

// Include sha2_ops.h FIRST to get the type definitions before we use them in macros
#include <oqs/sha2_ops.h>
#include <oqs/sha2.h>

// PQClean expects these macro names mapped to liboqs functions
#define sha256                 OQS_SHA2_sha256
#define sha512                 OQS_SHA2_sha512

#define sha256ctx              OQS_SHA2_sha256_ctx
#define sha256_inc_init        OQS_SHA2_sha256_inc_init
#define sha256_inc_ctx_clone   OQS_SHA2_sha256_inc_ctx_clone
#define sha256_inc_blocks      OQS_SHA2_sha256_inc_blocks
#define sha256_inc_finalize    OQS_SHA2_sha256_inc_finalize
#define sha256_inc_ctx_release OQS_SHA2_sha256_inc_ctx_release

#define sha512ctx              OQS_SHA2_sha512_ctx
#define sha512_inc_init        OQS_SHA2_sha512_inc_init
#define sha512_inc_ctx_clone   OQS_SHA2_sha512_inc_ctx_clone
#define sha512_inc_blocks      OQS_SHA2_sha512_inc_blocks
#define sha512_inc_finalize    OQS_SHA2_sha512_inc_finalize
#define sha512_inc_ctx_release OQS_SHA2_sha512_inc_ctx_release

#endif // OQS_SHIMS_SHA2_H


