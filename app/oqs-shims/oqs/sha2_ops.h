#ifndef OQS_SHA2_OPS_H
#define OQS_SHA2_OPS_H

#include <stddef.h>
#include <stdint.h>

#include <oqs/common.h>

#if defined(__cplusplus)
extern "C" {
#endif

// Copy the type definitions from sha2_ops.h (needed before sha2.h uses them)
typedef struct {
	void *ctx;
	size_t data_len;
	uint8_t data[128];
} OQS_SHA2_sha224_ctx;

typedef struct {
	void *ctx;
	size_t data_len;
	uint8_t data[128];
} OQS_SHA2_sha256_ctx;

typedef struct {
	void *ctx;
	size_t data_len;
	uint8_t data[128];
} OQS_SHA2_sha384_ctx;

typedef struct {
	void *ctx;
	size_t data_len;
	uint8_t data[128];
} OQS_SHA2_sha512_ctx;

struct OQS_SHA2_callbacks {
	void (*SHA2_sha256)(uint8_t *output, const uint8_t *input, size_t inplen);
	void (*SHA2_sha256_inc_init)(OQS_SHA2_sha256_ctx *state);
	void (*SHA2_sha256_inc_ctx_clone)(OQS_SHA2_sha256_ctx *dest, const OQS_SHA2_sha256_ctx *src);
	void (*SHA2_sha256_inc)(OQS_SHA2_sha256_ctx *state, const uint8_t *in, size_t len);
	void (*SHA2_sha256_inc_blocks)(OQS_SHA2_sha256_ctx *state, const uint8_t *in, size_t inblocks);
	void (*SHA2_sha256_inc_finalize)(uint8_t *out, OQS_SHA2_sha256_ctx *state, const uint8_t *in, size_t inlen);
	void (*SHA2_sha256_inc_ctx_release)(OQS_SHA2_sha256_ctx *state);
	void (*SHA2_sha384)(uint8_t *output, const uint8_t *input, size_t inplen);
	void (*SHA2_sha384_inc_init)(OQS_SHA2_sha384_ctx *state);
	void (*SHA2_sha384_inc_ctx_clone)(OQS_SHA2_sha384_ctx *dest, const OQS_SHA2_sha384_ctx *src);
	void (*SHA2_sha384_inc_blocks)(OQS_SHA2_sha384_ctx *state, const uint8_t *in, size_t inblocks);
	void (*SHA2_sha384_inc_finalize)(uint8_t *out, OQS_SHA2_sha384_ctx *state, const uint8_t *in, size_t inlen);
	void (*SHA2_sha384_inc_ctx_release)(OQS_SHA2_sha384_ctx *state);
	void (*SHA2_sha512)(uint8_t *output, const uint8_t *input, size_t inplen);
	void (*SHA2_sha512_inc_init)(OQS_SHA2_sha512_ctx *state);
	void (*SHA2_sha512_inc_ctx_clone)(OQS_SHA2_sha512_ctx *dest, const OQS_SHA2_sha512_ctx *src);
	void (*SHA2_sha512_inc_blocks)(OQS_SHA2_sha512_ctx *state, const uint8_t *in, size_t inblocks);
	void (*SHA2_sha512_inc_finalize)(uint8_t *out, OQS_SHA2_sha512_ctx *state, const uint8_t *in, size_t inlen);
	void (*SHA2_sha512_inc_ctx_release)(OQS_SHA2_sha512_ctx *state);
};

OQS_API void OQS_SHA2_set_callbacks(struct OQS_SHA2_callbacks *new_callbacks);

#if defined(__cplusplus)
} // extern "C"
#endif

#endif // OQS_SHA2_OPS_H

