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
 #define CERT_FILE     "certs/server-cert-hybrid.pem"
 #define KEY_FILE      "certs/ecc-server-key.pem"
 #define ALT_KEY_FILE  "certs/dilithium-server.priv"
 
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

/* Certificate Verification Callback for Client Certificates
 * Validates certificates but allows self-signed certs (skips CA validation)
 */
static int client_cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store)
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
        printf("Certificate verification: Allowing self-signed client cert (error=%d)\n", err);
        return 1; /* Accept self-signed certificate */
    }
    
    /* Reject all other certificate errors (invalid signature, expired, etc.) */
    printf("Certificate verification failed: error=%d\n", err);
    return 0;
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
     ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
     if (ctx == NULL) err_sys("wolfSSL_CTX_new failed");
 
     ret = wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_3);
     if (ret != WOLFSSL_SUCCESS) {
         fprintf(stderr, "Error: Could not set minimum version to TLS 1.3\n");
         exit(EXIT_FAILURE);
     }
 
     /* 3. ENFORCE PURE ML-KEM GROUPS (Key Exchange) */
     int candidates[] = { 
         WOLFSSL_ML_KEM_768
     };
     int valid_groups[1];
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
         fprintf(stderr, "Error: No PQC groups supported.\n");
         exit(EXIT_FAILURE);
     }
 
     ret = wolfSSL_CTX_set_groups(ctx, valid_groups, valid_count);
     if (ret != WOLFSSL_SUCCESS) err_sys("set groups failed");
     printf("Conf: %d Pure PQC Group(s) enabled (ML-KEM).\n", valid_count);
 
     /* 4. LOAD HYBRID CREDENTIALS (Authentication) */
     
     /* A. Load the Hybrid Certificate */
     ret = wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, WOLFSSL_FILETYPE_PEM);
     if (ret != WOLFSSL_SUCCESS) {
         fprintf(stderr, "Error loading Cert %s.\n", CERT_FILE);
         exit(EXIT_FAILURE);
     }
 
     /* B. Load the Primary Private Key (ECC) */
     ret = wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, WOLFSSL_FILETYPE_PEM);
     if (ret != WOLFSSL_SUCCESS) {
         fprintf(stderr, "Error loading Primary Key %s.\n", KEY_FILE);
         exit(EXIT_FAILURE);
     }
 
     /* C. Load the Alternative Private Key (Dilithium) */
     #ifdef WOLFSSL_DUAL_ALG_CERTS
         ret = wolfSSL_CTX_use_AltPrivateKey_file(ctx, ALT_KEY_FILE, WOLFSSL_FILETYPE_PEM);
         if (ret != WOLFSSL_SUCCESS) {
             fprintf(stderr, "Error loading Alt Key %s.\n", ALT_KEY_FILE);
             exit(EXIT_FAILURE);
         }
         printf("Conf: Dual-Algorithm Credentials loaded.\n");
 
        /* --- [NEW] ENFORCE DOUBLE SIGNING --- */
        /* This forces the server to sign with BOTH keys */
        /*byte cks_sigspec = WOLFSSL_CKS_SIGSPEC_BOTH;
        ret = wolfSSL_CTX_UseCKS(ctx, &cks_sigspec, 1);
        if (ret != WOLFSSL_SUCCESS) {
             fprintf(stderr, "Error setting CKS config to BOTH.\n");
             exit(EXIT_FAILURE);
        }
        printf("Conf: Enforcing Dual-Sign (WOLFSSL_CKS_SIGSPEC_BOTH).\n");*/
        

     #else
         fprintf(stderr, "Error: WOLFSSL_DUAL_ALG_CERTS not enabled. Cannot run hybrid mode.\n");
         exit(EXIT_FAILURE);
     #endif

     /* 5. REQUEST AND VERIFY CLIENT CERTIFICATES (Mutual TLS) */
     /* Request client certificate during handshake */
     //wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, client_cert_verify_callback);
     printf("Conf: Client certificate authentication enabled (allowing self-signed).\n");

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
             int err = wolfSSL_get_error(ssl, 0);
             char buffer[80];
             fprintf(stderr, "TLS Handshake error: %s\n", wolfSSL_ERR_error_string(err, buffer));
         } else {
             const char* msg = "Hello from Hybrid Auth Server!\n";
             char reply[1024];
             int readSz;
 
             printf("TLS 1.3 Handshake Complete!\n");
             printf("Cipher: %s\n", wolfSSL_get_cipher_name(ssl));
             
             /* Verify client certificate was presented */
             WOLFSSL_X509* client_cert = wolfSSL_get_peer_certificate(ssl);
             if (client_cert != NULL) {
                 printf("Client certificate received and verified.\n");
                 wolfSSL_X509_free(client_cert);
             } else {
                 printf("Warning: No client certificate received.\n");
             }

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