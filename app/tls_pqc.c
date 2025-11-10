#include "tls_pqc.h"
#include "usb_device.h"
#include "os.h"
#include "time.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>
#include <string.h>

/* TLS I/O buffer for USB */
#define TLS_IO_BUFFER_SIZE (16*1024)
static u8 tls_rx_buffer[TLS_IO_BUFFER_SIZE];
static size_t tls_rx_wr_ptr = 0;
static size_t tls_rx_rd_ptr = 0;
static size_t tls_rx_count = 0;

/* TLS I/O context */
static void *tls_io_ctx = NULL;

/* TLS first record debug capture */
static u8 tls_first_record[256];
static int tls_first_record_len = 0;

/* TLS active flag - set when handshake is in progress */
static bool tls_active = false;

/* Forward declarations */
static int tls_usb_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx);
static int tls_usb_send(WOLFSSL* ssl, char* buf, int sz, void* ctx);

/* USB RX handler for TLS data - called from USB interrupt/task */
void tls_pqc_usb_rx_handler(u8 *data, u32 len)
{
    u32 i;

    for (i = 0; i < len; i++) {
        if (tls_rx_count >= TLS_IO_BUFFER_SIZE) {
            OS_ERROR("TLS RX overflow");
            return;
        }

        tls_rx_wr_ptr++;
        if (tls_rx_wr_ptr >= TLS_IO_BUFFER_SIZE) {
            tls_rx_wr_ptr = 0;
        }

        tls_rx_buffer[tls_rx_wr_ptr] = data[i];
        tls_rx_count++;
    }
}

/* Custom I/O recv callback for wolfSSL */
static int tls_usb_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)ctx;
    
    int bytes_read = 0;
    
    /* Process USB to receive any pending data */
    usb_device_task();
    
    while (bytes_read < sz && tls_rx_count > 0) {
        tls_rx_rd_ptr++;
        if (tls_rx_rd_ptr >= TLS_IO_BUFFER_SIZE) {
            tls_rx_rd_ptr = 0;
        }
        
        buf[bytes_read++] = (char)tls_rx_buffer[tls_rx_rd_ptr];
        tls_rx_count--;
    }
    
    /* Return bytes read, or WOLFSSL_CBIO_ERR_WANT_READ if no data available */
    if (bytes_read == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    
    return bytes_read;
}

/* Custom I/O send callback for wolfSSL */
static int tls_usb_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)ctx;
    
    if (!usb_device_connected()) {
        return WOLFSSL_CBIO_ERR_CONN_RST;
    }
    
    /* Process USB task to ensure TX path is ready */
    usb_device_task();

    /* Capture the first TLS record for debugging */
    if (tls_first_record_len == 0) {
        int copy = sz;
        if (copy > (int)sizeof(tls_first_record)) {
            copy = sizeof(tls_first_record);
        }
        memcpy(tls_first_record, buf, (size_t)copy);
        tls_first_record_len = copy;
    }
    
    /* Send data via USB with retries */
    int retries = 200;  /* Increased retries for better reliability */
    usb_result_e result;
    
    while (retries > 0) {
        result = usb_cdc_tx((u8*)buf, (u16)sz);
        if (result == USB_RESULT_OK) {
            /* Data queued successfully, process USB multiple times to ensure transmission */
            usb_device_task();
            OS_DELAY(2);
            usb_device_task();
            OS_DELAY(2);
            usb_device_task();
            return sz;
        }
        
        /* USB busy, wait and retry */
        OS_DELAY(2);
        usb_device_task();
        retries--;
    }
    
    /* Failed to send after retries */
    return WOLFSSL_CBIO_ERR_WANT_WRITE;
}

bool tls_pqc_selftest(void)
{
    int ret;
    bool ok = false;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    wolfSSL_Init();

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        OS_PRINTF("TLS: CTX_new failed" NL);
        goto done;
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        OS_PRINTF("TLS: SSL_new failed" NL);
        goto done;
    }

    /* Select pure PQC group: ML-KEM-768 */
    ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_ML_KEM_768);
    if (ret != WOLFSSL_SUCCESS) {
        OS_PRINTF("TLS: UseKeyShare failed" NL);
        goto done;
    }

    /* Set custom I/O callbacks */
    wolfSSL_SSLSetIORecv(ssl, tls_usb_recv);
    wolfSSL_SSLSetIOSend(ssl, tls_usb_send);
    wolfSSL_SetIOReadCtx(ssl, tls_io_ctx);
    wolfSSL_SetIOWriteCtx(ssl, tls_io_ctx);

    ok = true;

done:
    if (ssl != NULL) {
        wolfSSL_free(ssl);
    }
    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
    }
    wolfSSL_Cleanup();
    return ok;
}

bool tls_pqc_is_active(void)
{
    return tls_active;
}

bool tls_pqc_handshake(void)
{
    int ret;
    bool ok = false;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    os_timer_t start_time, timeout;
    const u32 timeout_ms = 30000; /* 30 second timeout */

    /* Clear TLS RX buffer - ensure it's completely empty */
    tls_rx_wr_ptr = 0;
    tls_rx_rd_ptr = 0;
    tls_rx_count = 0;
    /* Clear buffer memory to avoid any stale data */
    memset(tls_rx_buffer, 0, sizeof(tls_rx_buffer));

    if (!usb_device_connected()) {
        OS_PRINTF("TLS: USB not connected" NL);
        return false;
    }

    /* Flush any pending USB data before starting TLS */
    usb_device_task();
    OS_DELAY(10);

    /* Mark TLS as active - this routes all USB RX to TLS handler */
    /* NOTE: No OS_PRINTF after this point - all USB data must be TLS data only! */
    tls_active = true;
    tls_first_record_len = 0;

    /* OS_PRINTF("TLS: Initializing..." NL); - Disabled: would corrupt TLS stream */
    /* Ensure wolfSSL is initialized (idempotent, safe to call multiple times) */
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        tls_active = false;
        OS_PRINTF("TLS: wolfSSL_Init failed" NL);
        return false;
    }

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    /* Initialize error tracking variables early */
    int last_err = 0;
    char last_err_str[80];
    last_err_str[0] = '\0';

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        last_err = -1;
        strncpy(last_err_str, "CTX_new failed", sizeof(last_err_str));
        last_err_str[sizeof(last_err_str) - 1] = '\0';
        goto done;
    }

    /* For testing, disable certificate verification until CA is provisioned */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

#ifdef SINGLE_THREADED
    /* Pre-initialize RNG on CTX for SINGLE_THREADED mode - this helps diagnose RNG issues */
    ret = wolfSSL_CTX_new_rng(ctx);
    if (ret != WOLFSSL_SUCCESS) {
        last_err = ret;
        strncpy(last_err_str, "CTX_new_rng failed (RNG init error)", sizeof(last_err_str));
        last_err_str[sizeof(last_err_str) - 1] = '\0';
        goto done;
    }
#endif

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        last_err = -1;  /* WOLFSSL_FATAL_ERROR */
        strncpy(last_err_str, "SSL_new failed (likely memory allocation)", sizeof(last_err_str));
        last_err_str[sizeof(last_err_str) - 1] = '\0';
        goto done;
    }

    /* Select pure PQC group: ML-KEM-768 */
    ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_ML_KEM_768);
    if (ret != WOLFSSL_SUCCESS) {
        last_err = ret;
        strncpy(last_err_str, "UseKeyShare failed", sizeof(last_err_str));
        last_err_str[sizeof(last_err_str) - 1] = '\0';
        goto done;
    }

    /* Set custom I/O callbacks */
    wolfSSL_SSLSetIORecv(ssl, tls_usb_recv);
    wolfSSL_SSLSetIOSend(ssl, tls_usb_send);
    wolfSSL_SetIOReadCtx(ssl, tls_io_ctx);
    wolfSSL_SetIOWriteCtx(ssl, tls_io_ctx);

    /* Make non-blocking for better control */
    wolfSSL_set_using_nonblock(ssl, 1);

    /* OS_PRINTF("TLS: Starting handshake..." NL); - Disabled: would corrupt TLS stream */
    start_time = timer_get_time();
    timeout = start_time + (timeout_ms * TIMER_MS);

    /* Ensure USB is ready before starting handshake */
    usb_device_task();
    OS_DELAY(20);  /* Give USB time to be fully ready */
    usb_device_task();

    /* Perform TLS handshake */
    while (1) {
        os_timer_t now = timer_get_time();
        if (now > timeout) {
            last_err = WOLFSSL_CBIO_ERR_TIMEOUT;
            strncpy(last_err_str, "timeout", sizeof(last_err_str));
            last_err_str[sizeof(last_err_str) - 1] = '\0';
            goto done;
        }

        /* Process USB before each connect attempt to ensure I/O is ready */
        usb_device_task();
        
        ret = wolfSSL_connect(ssl);
        
        if (ret == WOLFSSL_SUCCESS) {
            ok = true;
            break;
        }

        int err = wolfSSL_get_error(ssl, ret);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            /* Need more data or can send more - continue */
            /* Process USB to receive/send data - do this multiple times to ensure data flows */
            usb_device_task();
            OS_DELAY(2);  /* Slightly longer delay to allow USB processing */
            usb_device_task();
            OS_DELAY(2);
            usb_device_task();
            continue;
        }

        /* Record the error so we can report it after TLS is torn down */
        last_err = err;
        /* Format error message based on error code */
        if (err == WOLFSSL_ERROR_WANT_READ) {
            strncpy(last_err_str, "WANT_READ", sizeof(last_err_str));
        } else if (err == WOLFSSL_ERROR_WANT_WRITE) {
            strncpy(last_err_str, "WANT_WRITE", sizeof(last_err_str));
        } else {
            strncpy(last_err_str, "TLS handshake error", sizeof(last_err_str));
        }
        last_err_str[sizeof(last_err_str) - 1] = '\0';
        /* Also check if this is a WANT_READ/WANT_WRITE that we missed */
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            /* This shouldn't happen here, but if it does, continue the loop */
            usb_device_task();
            OS_DELAY(2);
            usb_device_task();
            OS_DELAY(2);
            usb_device_task();
            continue;
        }
        goto done;
    }

done:
    if (ssl != NULL) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
    }
    wolfSSL_Cleanup();
    
    /* Clear TLS RX buffer */
    tls_rx_wr_ptr = 0;
    tls_rx_rd_ptr = 0;
    tls_rx_count = 0;
    
    /* Mark TLS as inactive - safe to print again */
    tls_active = false;
    
    /* Flush any remaining USB data to ensure TLS stream is complete */
    usb_device_task();
    
    /* Now we can safely print status messages */
    if (ok) {
        OS_PRINTF("TLS: Handshake complete!" NL);
    } else {
        if (last_err != 0) {
            /* Sanitize error string */
            if (last_err_str[0] != '\0') {
                for (int i = 0; i < (int)sizeof(last_err_str) && last_err_str[i] != '\0'; ++i) {
                    unsigned char c = (unsigned char)last_err_str[i];
                    if ((c < 32 && c != '\n' && c != '\r' && c != '\t') || c > 126) {
                        last_err_str[i] = '?';
                    }
                }
            }
            /* Print error with code interpretation */
            const char* err_name = "unknown";
            if (last_err == WOLFSSL_ERROR_WANT_READ) err_name = "WANT_READ";
            else if (last_err == WOLFSSL_ERROR_WANT_WRITE) err_name = "WANT_WRITE";
            else if (last_err == WOLFSSL_CBIO_ERR_TIMEOUT) err_name = "TIMEOUT";
            else if (last_err == WOLFSSL_CBIO_ERR_CONN_RST) err_name = "CONN_RST";
            else if (last_err == WOLFSSL_CBIO_ERR_WANT_READ) err_name = "CBIO_WANT_READ";
            else if (last_err == WOLFSSL_CBIO_ERR_WANT_WRITE) err_name = "CBIO_WANT_WRITE";
            else if (last_err == MEMORY_E) err_name = "MEMORY_E";
            else if (last_err == RNG_FAILURE_E) err_name = "RNG_FAILURE_E";
            else if (last_err == WC_HW_E) err_name = "WC_HW_E";
            
            const char* msg = (last_err_str[0] != '\0') ? last_err_str : "none";
            OS_PRINTF("TLS: Handshake failed (err=%d/%s, msg=%s)" NL,
                      last_err, err_name, msg);
        } else {
            OS_PRINTF("TLS: Handshake failed (no error code)" NL);
        }
    }

    /* Debug: Check if send callback was ever called */
    if (tls_first_record_len > 0) {
        OS_PRINTF("TLS: First record (%d bytes): ", tls_first_record_len);
        for (int i = 0; i < tls_first_record_len; ++i) {
            OS_PRINTF("%02X", tls_first_record[i]);
        }
        OS_PRINTF(NL);
    } else {
        OS_PRINTF("TLS: Send callback was never called (no data sent)" NL);
    }
    
    return ok;
}


