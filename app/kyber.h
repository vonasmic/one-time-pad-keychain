#ifndef KYBER_H
#define KYBER_H

#include "type.h"

bool kyber_init(void);

u32 kyber_ciphertext_len(void);
u32 kyber_sharedsecret_len(void);

bool kyber_encapsulate(u8 *ct_out, u8 *ss_out, u32 *time_us);

bool kyber_decapsulate(const u8 *ct, u8 *ss_out, u32 *time_us);

#endif // KYBER_H



