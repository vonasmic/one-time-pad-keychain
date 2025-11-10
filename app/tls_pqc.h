#ifndef TLS_PQC_H
#define TLS_PQC_H

#include <stdbool.h>
#include "type.h"

/* Initializes a TLS 1.3 client context and selects ML-KEM group.
 * Note: Does not perform a handshake; transport I/O is not configured here.
 */
bool tls_pqc_selftest(void);

/* Performs a TLS 1.3 handshake over USB using ML-KEM-768.
 * Returns true if handshake succeeds, false otherwise.
 */
bool tls_pqc_handshake(void);

/* USB RX handler for TLS data - must be called from USB RX callback
 * when TLS handshake is active. This bypasses the normal TTY parser.
 */
void tls_pqc_usb_rx_handler(u8 *data, u32 len);

/* Check if TLS handshake is currently active */
bool tls_pqc_is_active(void);

#endif /* TLS_PQC_H */


