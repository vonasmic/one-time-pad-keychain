#ifndef SPHINCS_H
#define SPHINCS_H

#include "type.h"

// Early initialization - sets up randombytes before any liboqs calls
void sphincs_init_early(void);

// Initialize SPHINCS+ context and keypair on first use. Returns true on success.
bool sphincs_init(void);

// Returns maximum signature length in bytes (0 if unavailable).
u32 sphincs_signature_max_len(void);

// Sign message; outputs signature to provided buffer, sets out_len, and returns true on success.
// If time_us is non-NULL, stores time taken (microseconds) for signing only.
bool sphincs_sign(const u8 *msg, u32 msg_len, u8 *sig_out, u32 *out_len, u32 *time_us);

// Verify signature; returns true on success. If time_us non-NULL, stores verify time (microseconds).
bool sphincs_verify(const u8 *msg, u32 msg_len, const u8 *sig, u32 sig_len, u32 *time_us);

#endif // SPHINCS_H


