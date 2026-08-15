/* pqc_server.c
 * A simplified wolfSSL server using Pure PQC Key Exchange (ML-KEM) 
 * and Hybrid Authentication (ECC + Dilithium Dual-Cert) with DOUBLE SIGNING.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <arpa/inet.h>
 #include <signal.h>
 #include <errno.h> 
 
 /* Configuration Constants */
 #define DEFAULT_PORT 11111
 
 /* CERTIFICATES: 
  * 1. CERT_FILE:     The Dual-Algorithm (Hybrid) Certificate.
  * 2. KEY_FILE:      The Primary ECC P-384 Private Key.
  * 3. ALT_KEY_FILE:  The Alternative Dilithium 3 Private Key.
  */
 #define NATIVE_SERVER_CERTS "../JAVA_TLS_TEST/certs/native/server"

 #define CERT_FILE     NATIVE_SERVER_CERTS "/server-cert-hybrid.pem"
 #define KEY_FILE      NATIVE_SERVER_CERTS "/ecc-server-key.pem"
 #define CA_CERT_FILE  NATIVE_SERVER_CERTS "/root-ca.pem"
 
 /* Global flag for shutdown */
 volatile int shutdown_flag = 0;
 
 void sig_handler(int signo) {
     if (signo == SIGINT) shutdown_flag = 1;
 }
 
/* Helper to check errors and exit */
void err_sys(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

 int main(int argc, char** argv) {
     int                 sockfd;
     int                 clientfd;
     struct sockaddr_in  servAddr;
     struct sockaddr_in  clientAddr;
     socklen_t           size = sizeof(clientAddr);
     WOLFSSL_CTX* ctx = NULL;
     WOLFSSL* ssl = NULL;
     int                 ret;
     struct sigaction    sa;
 
     /* 1. Initialize wolfSSL */
     wolfSSL_Init();
     
     /* Check for PQC support */
     #if !defined(HAVE_PQC)
         fprintf(stderr, "Error: wolfSSL was not compiled with PQC support.\n");
         return -1;
     #endif
 
     /* 2. Create Context */
     /* Use TLS 1.3 specifically as Hybrid Auth is a TLS 1.3 extension */
     ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
     if (ctx == NULL) err_sys("wolfSSL_CTX_new failed");
 
     ret = wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_3);
     if (ret != WOLFSSL_SUCCESS) {
         fprintf(stderr, "Error: Could not set minimum version to TLS 1.3\n");
         exit(EXIT_FAILURE);
     }
 
    /* Standalone ML-KEM768 (JAVA_TLS_TEST) with hybrid fallback for native clients. */
    int candidates[] = {
        WOLFSSL_ML_KEM_768,
        WOLFSSL_SECP256R1MLKEM768,
        WOLFSSL_X25519MLKEM768
    };
    int valid_groups[sizeof(candidates) / sizeof(candidates[0])];
     int valid_count = 0;
     int num_candidates = sizeof(candidates)/sizeof(candidates[0]);
     
     int i;
     for(i = 0; i < num_candidates; i++) {
         ret = wolfSSL_CTX_set_groups(ctx, &candidates[i], 1);
         if (ret == WOLFSSL_SUCCESS) {
             valid_groups[valid_count++] = candidates[i];
         }
     }
 
     if (valid_count == 0) {
        fprintf(stderr,
            "Error: No supported ML-KEM groups.\n");
        fprintf(stderr,
            "Rebuild wolfSSL with --enable-tls-mlkem-standalone and hybrid support.\n");
        exit(EXIT_FAILURE);
    }
    //wolfSSL_Debugging_ON();
    ret = wolfSSL_CTX_set_groups(ctx, valid_groups, valid_count);
    if (ret != WOLFSSL_SUCCESS) err_sys("set groups failed");
    printf("Conf: %d ML-KEM group(s) enabled.\n", valid_count);
 
     /* 4. LOAD HYBRID CREDENTIALS (Authentication) */
     
     /* A. Load the Hybrid Certificate */
     ret = wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, WOLFSSL_FILETYPE_PEM);
     if (ret != WOLFSSL_SUCCESS) {
         fprintf(stderr, "Error loading Cert %s.\n", CERT_FILE);
         fprintf(stderr, "Generate: cd tls_native && ./gen_native_certs.sh\n");
         exit(EXIT_FAILURE);
     }
 
     /* B. Load the Primary Private Key (ECC) */
     ret = wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, WOLFSSL_FILETYPE_PEM);
     if (ret != WOLFSSL_SUCCESS) {
         fprintf(stderr, "Error loading Primary Key %s.\n", KEY_FILE);
         fprintf(stderr, "Generate: cd tls_native && ./gen_native_certs.sh\n");
         exit(EXIT_FAILURE);
     }
 
     printf("Conf: Server credentials loaded.\n");

    if (wolfSSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading CA Cert %s.\n", CA_CERT_FILE);
        fprintf(stderr, "Generate native certs: cd tls_native && ./gen_native_certs.sh\n");
        fprintf(stderr, "  (or: make certs-native). Run from JAVA_TLS_TEST for JNI paths.\n");
        exit(EXIT_FAILURE);
    }

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    printf("Conf: Client certificate authentication enabled (strict CA verification).\n");

     /* 6. Socket Setup (Standard) */
     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) err_sys("socket creation failed");
 
     int on = 1;
     setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
 
     memset(&servAddr, 0, sizeof(servAddr));
     servAddr.sin_family = AF_INET;
     servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
     servAddr.sin_port = htons(DEFAULT_PORT);
 
     if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0)
         err_sys("bind failed");
 
     if (listen(sockfd, 5) < 0)
         err_sys("listen failed");
 
     sa.sa_handler = sig_handler;
     sigemptyset(&sa.sa_mask);
     sa.sa_flags = 0;
     sigaction(SIGINT, &sa, NULL);
 
     printf("Server listening on port %d... (Ctrl+C to stop)\n", DEFAULT_PORT);

     /* 7. Main Loop */
     while (!shutdown_flag) {
         clientfd = accept(sockfd, (struct sockaddr*)&clientAddr, &size);
         if (clientfd == -1) {
             if (errno == EINTR || shutdown_flag) break;
             perror("accept failed");
             continue;
         }
 
         printf("Connection accepted.\n");
 
        ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            fprintf(stderr, "wolfSSL_new failed\n");
            close(clientfd);
            continue;
        }

        wolfSSL_set_fd(ssl, clientfd);

         if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
             int ssl_err = wolfSSL_get_error(ssl, 0);
             char buffer[80];
             unsigned long lib_err = wolfSSL_ERR_get_error();
             if (lib_err != 0) {
                 fprintf(stderr, "TLS Handshake error: %s (ssl_err=%d)\n",
                     wolfSSL_ERR_error_string(lib_err, buffer), ssl_err);
             } else {
                 fprintf(stderr, "TLS Handshake error: %s (ssl_err=%d)\n",
                     wolfSSL_ERR_error_string(ssl_err, buffer), ssl_err);
             }
             fprintf(stderr,
                 "  Regenerate certs: ./gen_native_certs.sh (P-384+Dilithium-3, not P-256+Dilithium-3).\n");
         } else {
             const char* msg = "Hello from Hybrid Auth Server!\n";
             char reply[1024];
             int readSz;
 
            printf("TLS 1.3 Handshake Complete!\n");
            printf("Cipher: %s\n", wolfSSL_get_cipher_name(ssl));

            if (wolfSSL_get_verify_result(ssl) != WOLFSSL_X509_V_OK) {
                fprintf(stderr, "Error: Client certificate verification failed.\n");
                wolfSSL_shutdown(ssl);
                wolfSSL_free(ssl);
                close(clientfd);
                continue;
            }
            printf("Client certificate verified against %s.\n", CA_CERT_FILE);

             readSz = wolfSSL_read(ssl, reply, sizeof(reply)-1);
             if (readSz > 0) {
                 reply[readSz] = '\0';
                 printf("Client said: %s\n", reply);
             }
             wolfSSL_write(ssl, msg, strlen(msg));
         }
 
         wolfSSL_shutdown(ssl);
         wolfSSL_free(ssl);
         close(clientfd);
     }
 
     wolfSSL_CTX_free(ctx);
     wolfSSL_Cleanup();
     close(sockfd);
     printf("\nServer shut down.\n");
 
     return 0;
 }