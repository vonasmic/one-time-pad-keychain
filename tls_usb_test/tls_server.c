/*
 * Simplified TLS 1.3 server for testing ML-KEM-768 handshake
 * with STM32U5 device
 *
 * Usage:
 *   1. Generate server certificate and key (if not exists):
 *      openssl req -x509 -newkey rsa:2048 -keyout server-key.pem \
 *        -out server-cert.pem -days 365 -nodes
 *
 *   2. Run server:
 *      ./tls_server [port]
 *
 *   3. Connect device via USB terminal and execute: TLS
 *
 * Note: The device uses USB for I/O, so you may need a USB-to-TCP bridge
 *       or modify the device to use TCP sockets instead of USB.
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#ifndef DEFAULT_PORT
#define DEFAULT_PORT 11111
#endif

static void print_usage(const char* progname)
{
    printf("Usage: %s [port] [cert_file] [key_file]\n", progname);
    printf("  port      - TCP port to listen on (default: %d)\n", DEFAULT_PORT);
    printf("  cert_file - Server certificate file (default: certs/server-cert.pem)\n");
    printf("  key_file  - Server private key file (default: certs/server-key.pem)\n");
    printf("\n");
    printf("This server supports TLS 1.3 with ML-KEM-768 for PQC testing.\n");
}

int main(int argc, char** argv)
{
    int port = DEFAULT_PORT;
    const char* cert_file = "certs/server-cert.pem";
    const char* key_file = "certs/server-key.pem";
    
    /* Parse command line arguments */
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Error: Invalid port number\n");
            return 1;
        }
    }
    if (argc > 2) {
        cert_file = argv[2];
    }
    if (argc > 3) {
        key_file = argv[3];
    }

    printf("TLS 1.3 Server with ML-KEM-768 support\n");
    printf("=======================================\n");
    printf("Port: %d\n", port);
    printf("Certificate: %s\n", cert_file);
    printf("Private Key: %s\n", key_file);
    printf("\n");

    /* Initialize wolfSSL */
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error: wolfSSL_Init failed\n");
        return 1;
    }

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    /* Create TLS 1.3 server context */
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!ctx) {
        fprintf(stderr, "Error: failed to create SSL context\n");
        wolfSSL_Cleanup();
        return 1;
    }

    /* Load server certificate */
    if (wolfSSL_CTX_use_certificate_file(ctx, cert_file, WOLFSSL_FILETYPE_PEM) 
        != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error: failed to load certificate file: %s\n", cert_file);
        fprintf(stderr, "Hint: Generate certificate with:\n");
        fprintf(stderr, "  openssl req -x509 -newkey rsa:2048 -keyout %s \\\n", key_file);
        fprintf(stderr, "    -out %s -days 365 -nodes\n", cert_file);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        return 1;
    }

    /* Load server private key */
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, key_file, WOLFSSL_FILETYPE_PEM) 
        != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error: failed to load private key file: %s\n", key_file);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        return 1;
    }

    /* Note: ML-KEM-768 key share will be set on each SSL object after creation */

    /* Create TCP socket */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        return 1;
    }

    /* Set socket options */
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sockfd);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        return 1;
    }

    /* Bind socket */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        return 1;
    }

    /* Listen for connections */
    if (listen(sockfd, 5) < 0) {
        perror("listen");
        close(sockfd);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        return 1;
    }

    printf("Server listening on port %d...\n", port);
    printf("Waiting for client connection...\n");
    printf("(Connect your device and execute: TLS)\n\n");

    /* Accept connections */
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
        if (clientfd < 0) {
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("\n[STAGE 1] Client connected from %s:%d\n", client_ip, ntohs(client_addr.sin_port));

        /* Create SSL object */
        printf("[STAGE 2] Creating SSL object...\n");
        WOLFSSL* ssl = wolfSSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "[ERROR] Failed to create SSL object\n");
            close(clientfd);
            continue;
        }
        printf("[STAGE 2] ✓ SSL object created\n");

        /* Set file descriptor */
        printf("[STAGE 3] Setting file descriptor...\n");
        if (wolfSSL_set_fd(ssl, clientfd) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "[ERROR] Failed to set file descriptor\n");
            wolfSSL_free(ssl);
            close(clientfd);
            continue;
        }
        printf("[STAGE 3] ✓ File descriptor set\n");

        /* Enable ML-KEM-768 key share for PQC */
        printf("[STAGE 4] Enabling ML-KEM-768 key share...\n");
#ifndef WOLFSSL_NO_ML_KEM_768
        if (wolfSSL_UseKeyShare(ssl, WOLFSSL_ML_KEM_768) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "[WARNING] Failed to enable ML-KEM-768, continuing anyway\n");
        } else {
            printf("[STAGE 4] ✓ ML-KEM-768 key share enabled\n");
        }
#else
        fprintf(stderr, "[WARNING] ML-KEM-768 not compiled in wolfSSL\n");
#endif

        /* Perform TLS handshake */
        printf("[STAGE 5] Starting TLS handshake (waiting for ClientHello)...\n");
        fflush(stdout);
        int ret = wolfSSL_accept(ssl);
        
        if (ret == WOLFSSL_SUCCESS) {
            printf("[STAGE 5] ✓ TLS handshake completed successfully!\n");
            
            /* Get connection info */
            printf("[STAGE 6] Retrieving connection information...\n");
            const char* version = wolfSSL_get_version(ssl);
            const char* cipher = wolfSSL_get_cipher(ssl);
            printf("  Version: %s\n", version ? version : "unknown");
            printf("  Cipher: %s\n", cipher ? cipher : "unknown");
            
            /* Read any data from client */
            printf("[STAGE 7] Waiting for data from client...\n");
            char buffer[1024];
            int bytes = wolfSSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                printf("[STAGE 7] ✓ Received from client (%d bytes): %s\n", bytes, buffer);
            } else if (bytes == 0) {
                printf("[STAGE 7] Client closed connection\n");
            } else {
                int read_err = wolfSSL_get_error(ssl, bytes);
                printf("[STAGE 7] Read error: %d\n", read_err);
            }
            
            /* Send response */
            printf("[STAGE 8] Sending response to client...\n");
            const char* response = "Hello from TLS server!";
            int write_ret = wolfSSL_write(ssl, response, strlen(response));
            if (write_ret > 0) {
                printf("[STAGE 8] ✓ Sent %d bytes to client\n", write_ret);
            } else {
                int write_err = wolfSSL_get_error(ssl, write_ret);
                printf("[STAGE 8] Write error: %d\n", write_err);
            }
            
            /* Shutdown gracefully */
            printf("[STAGE 9] Shutting down TLS connection...\n");
            wolfSSL_shutdown(ssl);
            printf("[STAGE 9] ✓ TLS shutdown complete\n");
        } else {
            int err = wolfSSL_get_error(ssl, ret);
            char err_str[256];
            wolfSSL_ERR_error_string_n(err, err_str, sizeof(err_str));
            printf("[STAGE 5] ✗ TLS handshake failed at stage 5\n");
            fprintf(stderr, "  Error code: %d\n", err);
            fprintf(stderr, "  Error message: %s\n", err_str);
            
            /* Provide more details about common errors */
            if (err == WOLFSSL_ERROR_WANT_READ) {
                fprintf(stderr, "  Details: Server waiting for more data from client\n");
            } else if (err == WOLFSSL_ERROR_WANT_WRITE) {
                fprintf(stderr, "  Details: Server needs to send more data\n");
            } else if (err == -311) {
                fprintf(stderr, "  Details: Unknown record type - client sent invalid TLS data\n");
                fprintf(stderr, "  This usually means non-TLS data was mixed with TLS handshake\n");
            }
        }

        /* Cleanup */
        wolfSSL_free(ssl);
        close(clientfd);
        printf("Connection closed.\n\n");
        printf("Waiting for next connection...\n");
    }

    /* Cleanup (never reached in this example) */
    close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}
