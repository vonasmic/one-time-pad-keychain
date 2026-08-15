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
#include <errno.h>
#include <arpa/inet.h>

#define SERVER_IP    "127.0.0.1"
#define SERVER_PORT  11111
#define CERTS_DIR           "../JAVA_TLS_TEST/certs"
#define CLIENT_CERT_FILE    CERTS_DIR "/client/client-cert.pem"
#define CLIENT_KEY_FILE     CERTS_DIR "/client/client-key.pem"
#define CA_CERT_FILE        CERTS_DIR "/root-ca.pem"

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
     const char*         server_addr = SERVER_IP;
     int                 server_port = SERVER_PORT;
     char*               port_end = NULL;
     long                parsed_port;

     if (argc > 3) {
         fprintf(stderr, "Usage: %s [address] [port]\n", argv[0]);
         return EXIT_FAILURE;
     }
     if (argc >= 2) {
         server_addr = argv[1];
     }
     if (argc >= 3) {
         errno = 0;
         parsed_port = strtol(argv[2], &port_end, 10);
         if (errno != 0 || port_end == argv[2] || *port_end != '\0' ||
             parsed_port < 1 || parsed_port > 65535) {
             fprintf(stderr, "Invalid port '%s'. Use a value from 1 to 65535.\n", argv[2]);
             return EXIT_FAILURE;
         }
         server_port = (int)parsed_port;
     }

     wolfSSL_Init();
 
     #if !defined(HAVE_PQC)
         fprintf(stderr, "Critical Error: 'HAVE_PQC' is not defined. Recompile wolfSSL with PQC support.\n");
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

    /* JAVA_TLS_TEST PURE_PQC uses standalone ML-KEM768; native tls_server uses hybrids. */
    int candidates[] = {
        WOLFSSL_ML_KEM_768,
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
        fprintf(stderr, "Error: No supported ML-KEM groups.\n");
        fprintf(stderr, "Rebuild wolfSSL with --enable-tls-mlkem-standalone for JAVA_TLS_TEST.\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_set_groups(ctx, valid_groups, valid_count) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error: Failed to set Groups.\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading client cert %s.\n", CLIENT_CERT_FILE);
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_FILE,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading client key %s.\n", CLIENT_KEY_FILE);
        exit(EXIT_FAILURE);
    }

    printf("Conf: Client credentials loaded.\n");

    if (wolfSSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading CA cert %s.\n", CA_CERT_FILE);
        exit(EXIT_FAILURE);
    }

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
 
     ssl = wolfSSL_new(ctx);
     if (ssl == NULL) err_sys("wolfSSL_new failed");
 
    if (wolfSSL_UseKeyShare(ssl, valid_groups[0]) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error: Failed to generate ML-KEM key share.\n");
        exit(EXIT_FAILURE);
    }
 
     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) err_sys("socket creation failed");

     memset(&servAddr, 0, sizeof(servAddr));
     servAddr.sin_family = AF_INET;
     servAddr.sin_port = htons(server_port);
     if (inet_pton(AF_INET, server_addr, &servAddr.sin_addr) != 1) {
         fprintf(stderr, "Invalid address '%s'\n", server_addr);
         return EXIT_FAILURE;
     }

     printf("Connecting to %s:%d...\n", server_addr, server_port);
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

    if (wolfSSL_get_verify_result(ssl) != WOLFSSL_X509_V_OK) {
        fprintf(stderr, "Error: Peer certificate verification failed.\n");
        fail_handshake_cleanup(ssl, ctx, sockfd);
    }
    printf("Peer certificate verified against %s.\n", CA_CERT_FILE);

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
