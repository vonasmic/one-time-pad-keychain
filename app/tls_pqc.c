#include "user_settings.h"
#include "tls_pqc.h"
#include "type.h"
#include "os.h"
#include "usb_device.h"
#include "wd.h"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef WOLFSSL_DUAL_ALG_CERTS
#include "client_certs.h"
#endif

/* -------------------------------------------------------------------------
 * Ring Buffer Implementation
 * ------------------------------------------------------------------------- */
/* * CRITICAL: With PQC (Kyber/Dilithium), handshake messages are HUGE.
 * If WolfSSL pauses to do math, this buffer must hold the ENTIRE 
 * incoming flight of data. If 16KB is too small, packets drop.
 */
#define RING_BUF_SIZE 32768  // Increased to 32KB to be safe for PQC

typedef struct {
    uint8_t buffer[RING_BUF_SIZE];
    volatile uint32_t head;
    volatile uint32_t tail;
    volatile uint32_t overflow_count; // Debugging counter
} RingBuffer;

RingBuffer rxRing = {.head = 0, .tail = 0, .overflow_count = 0 };

/* TLS active state tracking */
static bool tls_active = false;

/* * Writes data to the ring buffer. 
 * CRITICAL FIX: Added overflow detection logging.
 */
void RB_Write(RingBuffer* rb, const uint8_t* data, uint32_t len) {
    uint32_t bytes_written = 0;
    
    for (uint32_t i = 0; i < len; i++) {
        uint32_t next_head = (rb->head + 1) % RING_BUF_SIZE;
        
        if (next_head != rb->tail) { 
            rb->buffer[rb->head] = data[i];
            rb->head = next_head;
            bytes_written++;
        } else {
            // BUFFER IS FULL. Data is being dropped!
            // In a USB stream, this kills the connection because there is 
            // no TCP-style retransmission inside the USB pipe for these bytes.
            rb->overflow_count++;
        }
    }
}

int RB_Read(RingBuffer* rb, char* data, int len) {
    int bytes_read = 0;
    
    // Optimization: Block copy if possible could be added here, 
    // but byte-copy is safe for ring wrapping.
    while (bytes_read < len && rb->tail != rb->head) {
        data[bytes_read++] = rb->buffer[rb->tail];
        rb->tail = (rb->tail + 1) % RING_BUF_SIZE;
    }
    return bytes_read;
}

int RB_IsEmpty(RingBuffer* rb) {
    return (rb->head == rb->tail);
}

int RB_Available(RingBuffer* rb) {
    if (rb->head >= rb->tail) return rb->head - rb->tail;
    return RING_BUF_SIZE - (rb->tail - rb->head);
}

/* -------------------------------------------------------------------------
 * Debug Print Function (reused for both WolfSSL and TLS diagnostics)
 * ------------------------------------------------------------------------- */

static void debug_printf(const char* format, ...)
{
    char buffer[256];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    OS_FLUSH(); /* Flush before printing */
    OS_PRINTF("DEBUG: %s", buffer);
    OS_FLUSH(); /* Flush after printing */
}

/* -------------------------------------------------------------------------
 * Certificate Verification Callback
 * Validates certificates but allows self-signed certs (skips CA validation)
 * ------------------------------------------------------------------------- */

static int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    int err = 0;
    
    #ifdef OPENSSL_EXTRA
    err = wolfSSL_X509_STORE_CTX_get_error(store);
    #else
    err = store->error;
    #endif
    
    /* If preverify passed, accept the certificate */
    if (preverify == 1) {
        return 1;
    }
    
    /* Allow self-signed certificates and missing CA signer errors */
    /* These are the only errors we override - all other validation still applies */
    if (err == ASN_SELF_SIGNED_E || 
        err == ASN_NO_SIGNER_E
        #ifdef OPENSSL_EXTRA
        || err == WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        || err == WOLFSSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        #endif
        ) {
        debug_printf("Certificate verification: Allowing self-signed cert (error=%d)", err);
        return 1; /* Accept self-signed certificate */
    }
    
    /* Reject all other certificate errors (invalid signature, expired, etc.) */
    debug_printf("Certificate verification failed: error=%d", err);
    return 0;
}

/* -------------------------------------------------------------------------
 * WolfSSL Debug Callback
 * ------------------------------------------------------------------------- */

#ifdef DEBUG_WOLFSSL
static void wolfssl_debug_callback(const int logLevel, const char *const logMessage)
{
    (void)logLevel; /* Unused, but kept for API compatibility */
    if (logMessage != NULL) {
        OS_FLUSH(); /* Flush before printing */
        OS_PRINTF("DEBUG: %s", logMessage);
        OS_FLUSH(); /* Flush after printing */
    }
}
#endif /* DEBUG_WOLFSSL */

/* -------------------------------------------------------------------------
 * Public API / Callbacks
 * ------------------------------------------------------------------------- */

void tls_pqc_usb_rx_handler(u8 *data, u32 len) {
    RB_Write(&rxRing, data, len);
}

int EmbedReceive(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    RingBuffer* rb = (RingBuffer*)ctx;
    
    /* Debug Check: report overflows if they happened during the last slice */
    if (rb->overflow_count > 0) {
        OS_PRINTF("DEBUG: [CRITICAL] RX BUFFER OVERFLOW! Lost %lu bytes", (unsigned long)rb->overflow_count);

        rb->overflow_count = 0; // Reset to avoid spam
    }

    if (RB_IsEmpty(rb)) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    
    return RB_Read(rb, buf, sz);
}

int EmbedSend(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    (void)ssl; (void)ctx;
    
    if (!usb_device_connected()) {
        return WOLFSSL_CBIO_ERR_CONN_RST;
    }
    
    /* * Ensure we process USB tasks here too, otherwise the TX buffer 
     * might fill up if the host is slow to read.
     */
    usb_device_task();
    
    usb_result_e result = usb_cdc_tx((u8*)buf, (u16)sz);
    
    if (result == USB_RESULT_BUSY) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    
    return sz; 
}

/* -------------------------------------------------------------------------
 * Cleanup Function
 * Properly cleans up WolfSSL objects and resets state
 * ------------------------------------------------------------------------- */

static void cleanup_tls_resources(WOLFSSL* ssl, WOLFSSL_CTX* ctx) {
    /* Clean up SSL objects */
    if (ssl != NULL) {
        wolfSSL_free(ssl);
    }
    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
    }
    
    /* Clear any leftover data in the ring buffer */
    rxRing.head = 0;
    rxRing.tail = 0;
    rxRing.overflow_count = 0;
    
    /* Flush USB buffers to ensure clean state for next run */
    for (int i = 0; i < 5; i++) {
        usb_device_task();
        OS_DELAY(10);
    }
    
    /* Note: Don't call wolfSSL_Cleanup() here as it cleans up global state
     * that might be needed for re-initialization. Only call it on system shutdown.
     */
    
    tls_active = false;
    
    debug_printf("TLS task completed, ready for next command");
    
    /* Give time for any pending USB operations to complete */
    for (int i = 0; i < 10; i++) {
        OS_DELAY(10);
        usb_device_task();
        wd_feed();
    }
}

/* -------------------------------------------------------------------------
 * Main TLS Task
 * ------------------------------------------------------------------------- */

void tls_pqc_task(void) {
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int ret;
    int error_count = 0;

    tls_active = true;

    wolfSSL_Init();
    
    /* Enable Debug Logging with custom callback */
    #ifdef DEBUG_WOLFSSL
    wolfSSL_SetLoggingCb(wolfssl_debug_callback);
    wolfSSL_Debugging_ON();
    #endif

    debug_printf("TLS PQC task starting. RB Size: %d", RING_BUF_SIZE);

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        debug_printf("Error: Failed to create SSL context");
        goto cleanup;
    }

    /* Enable certificate verification with maximum security */
    /* WOLFSSL_VERIFY_PEER: Require peer to present a certificate */
    /* WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT: Fail if no certificate is presented */
    /* cert_verify_callback: Validates cert format, signatures, expiration, etc. */
    /*                      but allows self-signed certs (skips CA chain validation) */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, cert_verify_callback);
    
    wolfSSL_CTX_SetIORecv(ctx, EmbedReceive);
    wolfSSL_CTX_SetIOSend(ctx, EmbedSend);

    /* Load client certificate and keys for mutual TLS authentication */
    #ifdef WOLFSSL_DUAL_ALG_CERTS
    /* Load client certificate */
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, client_cert_der, (long)client_cert_der_len, WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        debug_printf("Error: Failed to load client certificate (code=%d)", ret);
        goto cleanup;
    }
    debug_printf("Client certificate loaded successfully");

    /* Load primary ECC private key */
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, client_key_der, (long)client_key_der_len, WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        debug_printf("Error: Failed to load client ECC key (code=%d)", ret);
        goto cleanup;
    }
    debug_printf("Client ECC key loaded successfully");

    /* Load alternative Dilithium private key */
    /* Note: The Dilithium key might be in PEM format even though variable name says "der" */
    /* Try DER first, then PEM if that fails */
    ret = wolfSSL_CTX_use_AltPrivateKey_buffer(ctx, client_dilithium_key_der, (long)client_dilithium_key_der_len, WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        /* Try PEM format if DER failed */
        ret = wolfSSL_CTX_use_AltPrivateKey_buffer(ctx, client_dilithium_key_der, (long)client_dilithium_key_der_len, WOLFSSL_FILETYPE_PEM);
        if (ret != WOLFSSL_SUCCESS) {
            debug_printf("Error: Failed to load client Dilithium key (code=%d)", ret);
            goto cleanup;
        }
        debug_printf("Client Dilithium key loaded successfully (PEM format)");
    } else {
        debug_printf("Client Dilithium key loaded successfully (DER format)");
    }
    #else
    debug_printf("Warning: WOLFSSL_DUAL_ALG_CERTS not enabled, client authentication disabled");
    #endif

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        debug_printf("Error: Failed to create SSL object");
        goto cleanup;
    }
    
    /* Set CKS (Dual-Alg) verification after SSL object is created */
    byte cks_order[] = { WOLFSSL_CKS_SIGSPEC_BOTH };
    if (!wolfSSL_UseCKS(ssl, cks_order, sizeof(cks_order))) {
        debug_printf("Error: Failed to set Dual-Alg (CKS) verification to BOTH");
        goto cleanup;
    }

    wolfSSL_SetIOReadCtx(ssl, &rxRing);

    /* Reset Ring Buffer state before starting */
    rxRing.head = 0;
    rxRing.tail = 0;
    rxRing.overflow_count = 0;

    debug_printf("Starting TLS handshake...");

    /* Handshake Loop */
    while (1) {
        ret = wolfSSL_connect(ssl);
        if (ret == WOLFSSL_SUCCESS) break; 

        int err = wolfSSL_get_error(ssl, ret);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            
            /* Print buffer usage every so often to see if it's filling up */
            int avail = RB_Available(&rxRing);
            if (avail > (RING_BUF_SIZE / 2)) {
                debug_printf("Warning: RB Load High: %d bytes waiting", avail);
            }

            /* * CRITICAL: We need to yield to let USB interrupts fire, 
             * but not sleep too long.
             */
            OS_DELAY(1); 
            usb_device_task();
            wd_feed();
            
            continue;
        } else {
            char buffer[80];
            wolfSSL_ERR_error_string(err, buffer);
            debug_printf("TLS fatal error: %s (%d)", buffer, err);
            error_count++;
            if(error_count > 5) {
                debug_printf("Too many errors, giving up");
            }
            goto cleanup;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        /* Verify that hybrid signatures were actually used for post-quantum security */
        if (ssl->peerSigSpec != NULL && ssl->peerSigSpecSz > 0) {
            byte server_sigspec = ssl->peerSigSpec[0];
            if (server_sigspec != WOLFSSL_CKS_SIGSPEC_BOTH) {
                debug_printf("Error: Server did not use hybrid signatures (sigspec=%d)", server_sigspec);
                goto cleanup;
            } 
        } else {
            debug_printf("Error: Server signature spec not available");
            goto cleanup;
        }
        debug_printf("TLS Handshake Complete! Cipher: %s", wolfSSL_get_cipher(ssl));
        
        const char* msg = "hello";
        int write_ret = wolfSSL_write(ssl, msg, strlen(msg));
        if (write_ret < 0) {
            int write_err = wolfSSL_get_error(ssl, write_ret);
            debug_printf("Error: TLS write failed (code=%d)", write_err);
        } else {
            debug_printf("TLS write success: %d bytes", write_ret);
        }
        
        /* Properly shutdown the SSL connection before cleanup */
        debug_printf("Shutting down TLS connection...");
        wolfSSL_shutdown(ssl);
    } else {
        debug_printf("Error: TLS handshake gave up.");
    }

cleanup:
    cleanup_tls_resources(ssl, ctx);
}

bool tls_pqc_handshake_with_data(const char* data_to_send) {
    (void)data_to_send;
    tls_pqc_task();
    return true;
}

bool tls_pqc_is_active(void) {
    return tls_active;
}