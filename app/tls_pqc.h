#ifndef TLS_PQC_H
#define TLS_PQC_H

#include <stdbool.h>
#include <stdint.h>

/* Include type.h if available (embedded build), otherwise provide minimal definitions */
/* Use __has_include if available (GCC extension, C23 feature) */
#if defined(__has_include)
    #if __has_include("type.h")
        #include "type.h"
    #else
        /* type.h not found - provide minimal type definitions for test environment */
        typedef unsigned char u8;
        typedef uint32_t u32;
        typedef unsigned char byte;
    #endif
#else
    /* __has_include not available - try to include type.h */
    /* If this fails, you may need to define u8 and u32 manually or provide type.h */
    #ifndef TYPE_H
        #include "type.h"
    #endif
    /* If type.h still not available after include attempt, define minimal types */
    #ifndef TYPE_H
        typedef unsigned char u8;
        typedef uint32_t u32;
        typedef unsigned char byte;
    #endif
#endif

/* Main TLS PQC task - performs TLS 1.3 handshake over USB */
void tls_pqc_task(void);

/* Performs a TLS 1.3 handshake over USB and sends data.
 * Currently sends "hello" after handshake completes.
 */
bool tls_pqc_handshake_with_data(const char* data_to_send);

/* USB RX handler for TLS data - must be called from USB RX callback */
void tls_pqc_usb_rx_handler(u8 *data, u32 len);

/* Check if TLS handshake is currently active */
bool tls_pqc_is_active(void);

#endif /* TLS_PQC_H */


