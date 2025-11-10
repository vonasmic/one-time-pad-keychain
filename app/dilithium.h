#ifndef DILITHIUM_H
#define DILITHIUM_H

#include "type.h"

bool dilithium_init(void);

u32 dilithium_signature_max_len(void);

bool dilithium_sign(const u8 *msg, u32 msg_len, u8 *sig_out, u32 *out_len, u32 *time_us);

bool dilithium_verify(const u8 *msg, u32 msg_len, const u8 *sig, u32 sig_len, u32 *time_us);

#endif // DILITHIUM_H



