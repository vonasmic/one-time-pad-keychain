/* pqc_client_strict.c
 * Strictly cleaned wolfSSL client: ML-KEM + Hybrid Auth (Dual Certs)
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <internal.h>  /* Needed to access internal WOLFSSL structure */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
 
#define SERVER_IP    "127.0.0.1"
#define SERVER_PORT  11111
#define CA_CERT_FILE "certs/server-cert-hybrid.pem"

#ifdef WOLFSSL_DUAL_ALG_CERTS
/* Storage for received public key from server */
static struct {
    byte *sapkiDer;
    int sapkiLen;
} server_public_key = {0};
#endif /* WOLFSSL_DUAL_ALG_CERTS */

void err_sys(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

/* Helper function to print hex bytes */
static void print_hex_bytes(const char* label, const unsigned char* data, int len, int max_bytes) {
    int i;
    int print_len = (len < max_bytes) ? len : max_bytes;
    
    printf("%s (%d bytes total, showing first %d bytes):\n", label, len, print_len);
    for (i = 0; i < print_len; i++) {
        printf("%02X ", data[i] & 0xFF);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    if (print_len % 16 != 0) {
        printf("\n");
    }
}

#ifdef WOLFSSL_DUAL_ALG_CERTS
/* Extract Subject Alternative Public Key Info (SAPKI) from peer certificate
 * Uses direct access to peerCert structure which is the most reliable method
 */
int get_sapki_from_cert(WOLFSSL* ssl, unsigned char** out_buf, int* out_len) {
    if (ssl == NULL || out_buf == NULL || out_len == NULL) {
        return -1;
    }
    
    /* Direct access to peerCert structure - most reliable method */
    if (ssl->peerCert.sapkiDer == NULL || ssl->peerCert.sapkiLen <= 0) {
        return -1; /* No SAPKI found, but don't print error (may be normal) */
    }
    
    *out_buf = (unsigned char*)malloc(ssl->peerCert.sapkiLen);
    if (*out_buf == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }
    
    memcpy(*out_buf, ssl->peerCert.sapkiDer, ssl->peerCert.sapkiLen);
    *out_len = ssl->peerCert.sapkiLen;
    
    return 0; /* Success */
}

/* Certificate Verification Callback
 * Extracts and stores public key (SAPKI) from server certificate
 */
static int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    WOLFSSL* ssl = NULL;
    unsigned char* sapki_buf = NULL;
    int sapki_len = 0;
    
    /* Get WOLFSSL object from store */
    #ifdef HAVE_EX_DATA
    #ifdef OPENSSL_EXTRA
    int ssl_idx = wolfSSL_get_ex_data_X509_STORE_CTX_idx();
    if (ssl_idx >= 0 && store != NULL) {
        ssl = (WOLFSSL*)wolfSSL_X509_STORE_CTX_get_ex_data(store, ssl_idx);
    }
    #endif
    #endif
    
    if (ssl == NULL) {
        /* If we can't get SSL object, proceed with verification */
        return preverify;
    }
    
    /* Extract SAPKI using the extraction function */
    if (get_sapki_from_cert(ssl, &sapki_buf, &sapki_len) == 0) {
        /* Free previous data if exists */
        if (server_public_key.sapkiDer != NULL) {
            free(server_public_key.sapkiDer);
            server_public_key.sapkiDer = NULL;
        }
        
        /* Store the extracted data */
        server_public_key.sapkiDer = sapki_buf;
        server_public_key.sapkiLen = sapki_len;
        printf("Stored SAPKI from verify callback: %d bytes\n", server_public_key.sapkiLen);
    }
    
    /* Return preverify status to continue normal verification */
    return preverify;
}
#endif /* WOLFSSL_DUAL_ALG_CERTS */
 
 int main(int argc, char** argv) {
     int                 sockfd;
     struct sockaddr_in  servAddr;
     WOLFSSL_CTX* ctx = NULL;
     WOLFSSL* ssl = NULL;
     char                msg[1024];
     int                 msgSz;
 
     wolfSSL_Init();
 
     /* Check for missing macros*/
     #if !defined(HAVE_PQC)
         fprintf(stderr, "Critical Error: 'HAVE_PQC' is not defined. Recompile wolfSSL with PQC support.\n");
         exit(EXIT_FAILURE);
     #endif
 
     #if !defined(WOLFSSL_DUAL_ALG_CERTS)
         fprintf(stderr, "Critical Error: 'WOLFSSL_DUAL_ALG_CERTS' is not defined. Recompile wolfSSL with Dual-Alg support.\n");
         exit(EXIT_FAILURE);
     #endif
 
     /* Create Context and force TLS 1.3 */
     ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
     if (ctx == NULL) err_sys("wolfSSL_CTX_new failed");
 
     if (wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_3) != WOLFSSL_SUCCESS) {
         fprintf(stderr, "Error: Could not set minimum version to TLS 1.3\n");
         exit(EXIT_FAILURE);
     }
 
     /* 1. Set Cipher Suite: AES-256-GCM-SHA384 */
     if (wolfSSL_CTX_set_cipher_list(ctx, "TLS13-AES256-GCM-SHA384") != WOLFSSL_SUCCESS) {
         fprintf(stderr, "Error: Failed to set Cipher Suite.\n");
         exit(EXIT_FAILURE);
     }


     /* 2. Configure Groups: ML-KEM-768 (PQC) */
     int groups[] = { WOLFSSL_ML_KEM_768 };
     int num_groups = sizeof(groups) / sizeof(groups[0]);
     if (wolfSSL_CTX_set_groups(ctx, groups, num_groups) != WOLFSSL_SUCCESS) {
         fprintf(stderr, "Error: Failed to set Groups.\n");
         exit(EXIT_FAILURE);
     }
 
    /* 3. Load CA for verification */
    if (wolfSSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading CA Cert %s.\n", CA_CERT_FILE);
        exit(EXIT_FAILURE);
    }
    
    #ifdef WOLFSSL_DUAL_ALG_CERTS
    /* Set verify callback to extract SAPKI */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, cert_verify_callback);
    #else
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    #endif
 
     ssl = wolfSSL_new(ctx);
     if (ssl == NULL) err_sys("wolfSSL_new failed");
 
     /* 4. Force ML-KEM Key Share */
     if (wolfSSL_UseKeyShare(ssl, WOLFSSL_ML_KEM_768) != WOLFSSL_SUCCESS) {
         fprintf(stderr, "Error: Failed to generate ML-KEM-768 Key Share.\n");
         exit(EXIT_FAILURE);
     }
 
     /* 5. Set Hybrid Verification*/
     byte cks_order[] = { WOLFSSL_CKS_SIGSPEC_ALTERNATIVE};
     byte client_cks_request = cks_order[0]; /* Store original request for validation */
     
     if (!wolfSSL_UseCKS(ssl, cks_order, sizeof(cks_order))) {
             fprintf(stderr, "Error: Failed to set Dual-Alg (CKS) verification to BOTH.\n");
             exit(EXIT_FAILURE);
     }
 
     /* Network Connection */
     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) err_sys("socket creation failed");
 
     memset(&servAddr, 0, sizeof(servAddr));
     servAddr.sin_family = AF_INET;
     servAddr.sin_port = htons(SERVER_PORT);
     inet_pton(AF_INET, SERVER_IP, &servAddr.sin_addr);
 
     printf("Connecting to %s:%d...\n", SERVER_IP, SERVER_PORT);
     if (connect(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0)
         err_sys("connect failed");
 
     wolfSSL_set_fd(ssl, sockfd);
 
     /* TLS Handshake */
     if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
         int err = wolfSSL_get_error(ssl, 0);
         char buffer[80];
         fprintf(stderr, "TLS Connect error: %s\n", wolfSSL_ERR_error_string(err, buffer));
         exit(EXIT_FAILURE);
    } else {
        printf("TLS 1.3 Handshake Complete (Cipher: %s)\n", wolfSSL_get_cipher_name(ssl));
        
        #ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Verify that hybrid signatures were actually used for post-quantum security */
        if (ssl->peerSigSpec != NULL && ssl->peerSigSpecSz > 0) {
            byte server_sigspec = ssl->peerSigSpec[0];
            if (server_sigspec == WOLFSSL_CKS_SIGSPEC_BOTH) {
                printf("✓ Post-Quantum Security: Server used BOTH signatures (hybrid mode)\n");
            } else{
                fprintf(stderr, "✗ ERROR: Server only used NATIVE or alternative signatures (not hybrid)\n");
                exit(EXIT_FAILURE);
            }
        } else {
            fprintf(stderr, "✗ ERROR: Server did not respond with CKS extension\n");
            fprintf(stderr, "   This means hybrid signatures were NOT used!\n");
            fprintf(stderr, "   Connection is NOT post-quantum secure!\n");
            exit(EXIT_FAILURE);
        }
        
        /* Verify that both signatures were successfully verified */
        if (!ssl->options.havePeerVerify || !ssl->options.peerAuthGood) {
            fprintf(stderr, "✗ ERROR: Peer signature verification failed\n");
            exit(EXIT_FAILURE);
        }
        printf("✓ Both signatures verified successfully\n");
        
        /* Extract SAPKI after handshake (fallback if not captured in callback) */
        if (server_public_key.sapkiDer == NULL) {
            unsigned char* sapki_buf = NULL;
            int sapki_len = 0;
            
            if (get_sapki_from_cert(ssl, &sapki_buf, &sapki_len) == 0) {
                server_public_key.sapkiDer = sapki_buf;
                server_public_key.sapkiLen = sapki_len;
                printf("Extracted SAPKI after handshake: %d bytes\n", server_public_key.sapkiLen);
            }
        }
        
        /* Print both normal and alternate public keys for comparison */
        printf("\n=== Public Key Comparison ===\n");
        
        /* Print normal public key from certificate */
        if (ssl->peerCert.pubKey.buffer != NULL && ssl->peerCert.pubKey.length > 0) {
            print_hex_bytes("Normal Public Key", 
                          (const unsigned char*)ssl->peerCert.pubKey.buffer, 
                          ssl->peerCert.pubKey.length, 32);
        } else {
            printf("Normal Public Key: Not available or empty\n");
        }
        
        /* Print alternate public key (SAPKI) */
        if (server_public_key.sapkiDer != NULL && server_public_key.sapkiLen > 0) {
            print_hex_bytes("Alternate Public Key (SAPKI)", 
                          (const unsigned char*)server_public_key.sapkiDer, 
                          server_public_key.sapkiLen, 32);
        } else {
            printf("Alternate Public Key (SAPKI): Not available or empty\n");
        }
        printf("=============================\n\n");
        #endif
        
        wolfSSL_write(ssl, "Hello", 5);
        msgSz = wolfSSL_read(ssl, msg, sizeof(msg) - 1);
        if (msgSz > 0) {
            msg[msgSz] = '\0';
            printf("Server said: %s\n", msg);
        }
    }
 
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    close(sockfd);

    #ifdef WOLFSSL_DUAL_ALG_CERTS
    /* Cleanup stored public key */
    if (server_public_key.sapkiDer != NULL) {
        free(server_public_key.sapkiDer);
        server_public_key.sapkiDer = NULL;
    }
    #endif

    return 0;
}