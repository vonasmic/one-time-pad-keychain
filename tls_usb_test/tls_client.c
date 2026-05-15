/* pqc_client_strict.c
 * Strictly cleaned wolfSSL client: ML-KEM + Hybrid Auth (Dual Certs)
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "tls_hybrid_verify.h"

#define SERVER_IP    "127.0.0.1"
#define SERVER_PORT  11111
#define NATIVE_CLIENT_CERTS  "../JAVA_TLS_TEST/certs/native/client"

#define CA_CERT_FILE         NATIVE_CLIENT_CERTS "/root-ca.pem"
#define CLIENT_CERT_FILE     NATIVE_CLIENT_CERTS "/server-cert-hybrid.pem"
#define CLIENT_KEY_FILE      NATIVE_CLIENT_CERTS "/ecc-server-key.pem"
#define CLIENT_ALT_KEY_FILE  NATIVE_CLIENT_CERTS "/dilithium-server.priv"

static const byte client_cks_order[] = {
    WOLFSSL_CKS_SIGSPEC_BOTH,
};

void err_sys(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void fail_handshake_cleanup(WOLFSSL* ssl, WOLFSSL_CTX* ctx, int sockfd)
{
    if (ssl != NULL) {
        wolfSSL_free(ssl);
    }
    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
    }
    wolfSSL_Cleanup();
    if (sockfd >= 0) {
        close(sockfd);
    }
    exit(EXIT_FAILURE);
}

 int main(int argc, char** argv) {
     int                 sockfd = -1;
     struct sockaddr_in  servAddr;
     WOLFSSL_CTX* ctx = NULL;
     WOLFSSL* ssl = NULL;
     char                msg[1024];
     int                 msgSz;
 
     wolfSSL_Init();
 
     #if !defined(HAVE_PQC)
         fprintf(stderr, "Critical Error: 'HAVE_PQC' is not defined. Recompile wolfSSL with PQC support.\n");
         exit(EXIT_FAILURE);
     #endif
 
     #if !defined(WOLFSSL_DUAL_ALG_CERTS)
         fprintf(stderr, "Critical Error: 'WOLFSSL_DUAL_ALG_CERTS' is not defined. Recompile wolfSSL with Dual-Alg support.\n");
         exit(EXIT_FAILURE);
     #endif
 
     ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
     if (ctx == NULL) err_sys("wolfSSL_CTX_new failed");
 
     if (wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_3) != WOLFSSL_SUCCESS) {
         fprintf(stderr, "Error: Could not set minimum version to TLS 1.3\n");
         exit(EXIT_FAILURE);
     }
 
     if (wolfSSL_CTX_set_cipher_list(ctx, "TLS13-AES256-GCM-SHA384") != WOLFSSL_SUCCESS) {
         fprintf(stderr, "Error: Failed to set Cipher Suite.\n");
         exit(EXIT_FAILURE);
     }

    int candidates[] = {
        WOLFSSL_SECP256R1MLKEM768,
        WOLFSSL_X25519MLKEM768
    };
    int valid_groups[sizeof(candidates) / sizeof(candidates[0])];
    int valid_count = 0;
    int num_candidates = sizeof(candidates) / sizeof(candidates[0]);
    int i;

    for (i = 0; i < num_candidates; i++) {
        if (wolfSSL_CTX_set_groups(ctx, &candidates[i], 1) == WOLFSSL_SUCCESS) {
            valid_groups[valid_count++] = candidates[i];
        }
    }

    if (valid_count == 0) {
        fprintf(stderr, "Error: No supported hybrid ML-KEM groups.\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_set_groups(ctx, valid_groups, valid_count) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error: Failed to set Groups.\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading Cert %s.\n", CLIENT_CERT_FILE);
        fprintf(stderr, "Generate: cd tls_usb_test && ./gen_native_certs.sh\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_FILE,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading Primary Key %s.\n", CLIENT_KEY_FILE);
        fprintf(stderr, "Generate: cd tls_usb_test && ./gen_native_certs.sh\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_use_AltPrivateKey_file(ctx, CLIENT_ALT_KEY_FILE,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading Alt Key %s.\n", CLIENT_ALT_KEY_FILE);
        fprintf(stderr, "Generate: cd tls_usb_test && ./gen_native_certs.sh\n");
        exit(EXIT_FAILURE);
    }
    printf("Conf: Dual-Algorithm Credentials loaded.\n");

    if (wolfSSL_CTX_UseCKS(ctx, (byte*)client_cks_order,
            sizeof(client_cks_order)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error setting CKS config to BOTH.\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading CA Cert %s.\n", CA_CERT_FILE);
        fprintf(stderr, "Generate native certs: cd tls_usb_test && ./gen_native_certs.sh\n");
        fprintf(stderr, "  (or: make certs-native)\n");
        exit(EXIT_FAILURE);
    }

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
 
     ssl = wolfSSL_new(ctx);
     if (ssl == NULL) err_sys("wolfSSL_new failed");
 
    if (wolfSSL_UseKeyShare(ssl, valid_groups[0]) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error: Failed to generate hybrid ML-KEM key share.\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_UseCKS(ssl, (byte*)client_cks_order,
            sizeof(client_cks_order)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error: Failed to set Dual-Alg (CKS) verification to BOTH.\n");
        exit(EXIT_FAILURE);
    }
 
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
 
     if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
         int err = wolfSSL_get_error(ssl, 0);
         char buffer[80];
         unsigned long libErr = wolfSSL_ERR_get_error();
         if (libErr != 0) {
             fprintf(stderr, "TLS Connect error: %s (ssl_err=%d)\n",
                 wolfSSL_ERR_error_string(libErr, buffer), err);
         } else {
             fprintf(stderr, "TLS Connect error: ssl_err=%d\n", err);
         }
         fail_handshake_cleanup(ssl, ctx, sockfd);
    }

    printf("TLS 1.3 Handshake Complete (Cipher: %s)\n",
        wolfSSL_get_cipher_name(ssl));

    if (!tls_verify_peer_cert(ssl)) {
        fail_handshake_cleanup(ssl, ctx, sockfd);
    }
    printf("Peer certificate verified against %s.\n", CA_CERT_FILE);

    if (!tls_require_local_dual_alt_sig(ssl)) {
        fail_handshake_cleanup(ssl, ctx, sockfd);
    }
    if (!tls_require_peer_dual_alt_sig(ssl)) {
        fail_handshake_cleanup(ssl, ctx, sockfd);
    }
    printf("Dual alt signature (CKS BOTH) confirmed.\n");

    wolfSSL_write(ssl, "Hello", 5);
    msgSz = wolfSSL_read(ssl, msg, sizeof(msg) - 1);
    if (msgSz > 0) {
        msg[msgSz] = '\0';
        printf("Server said: %s\n", msg);
    }
 
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    close(sockfd);

    return 0;
}
