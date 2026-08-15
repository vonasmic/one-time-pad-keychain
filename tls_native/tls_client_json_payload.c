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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>

#define SERVER_IP    "127.0.0.1"
#define SERVER_PORT  11111
#define CERTS_DIR           "../JAVA_TLS_TEST/certs"
#define CLIENT_CERT_FILE    CERTS_DIR "/client/client-cert.pem"
#define CLIENT_KEY_FILE     CERTS_DIR "/client/client-key.pem"
#define CA_CERT_FILE        CERTS_DIR "/root-ca.pem"
#define FRIEND_CERT_FILE    CERTS_DIR "/Alice.pem"
#define MAX_PUBKEY_DER_SZ   4096

static int tls_write_all(WOLFSSL* ssl, const void* data, size_t len)
{
    const unsigned char* p = (const unsigned char*)data;
    size_t written_total = 0;

    if (ssl == NULL || (data == NULL && len != 0)) {
        return WOLFSSL_FAILURE;
    }

    while (written_total < len) {
        size_t remaining = len - written_total;
        int chunk_sz = remaining > 4096 ? 4096 : (int)remaining;
        int written = wolfSSL_write(ssl, p + written_total, chunk_sz);

        if (written <= 0) {
            return WOLFSSL_FAILURE;
        }
        written_total += (size_t)written;
    }

    return WOLFSSL_SUCCESS;
}

#define TLS_WRITE_LITERAL(ssl, literal) \
    tls_write_all((ssl), (literal), sizeof(literal) - 1)

void err_sys(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static int credential_files_readable(void)
{
    return access(CLIENT_CERT_FILE, R_OK) == 0 &&
           access(CLIENT_KEY_FILE, R_OK) == 0 &&
           access(CA_CERT_FILE, R_OK) == 0 &&
           access(FRIEND_CERT_FILE, R_OK) == 0;
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

static int read_public_key_from_cert(const char* cert_file,
                                     unsigned char* out,
                                     size_t out_sz,
                                     size_t* out_len)
{
    enum {
        MAX_ECC_PUBKEY_DER_SZ = 128,
        MAX_ALT_PUBKEY_DER_SZ = DILITHIUM_LEVEL3_PUB_KEY_DER_SIZE,
        MAX_COMBINED_KEY_SZ = MAX_ECC_PUBKEY_DER_SZ + MAX_ALT_PUBKEY_DER_SZ
    };
    WOLFSSL_X509* cert = NULL;
    DecodedCert decoded;
    int decoded_init = 0;
    int cert_der_sz = 0;
    const unsigned char* cert_der = NULL;
    unsigned char ecc_pubkey_buf[MAX_ECC_PUBKEY_DER_SZ];
    int ecc_pubkey_sz = (int)sizeof(ecc_pubkey_buf);
    int alt_pubkey_info_sz;

    if (cert_file == NULL || out == NULL || out_len == NULL) {
        return WOLFSSL_FAILURE;
    }
    *out_len = 0;
    cert = wolfSSL_X509_load_certificate_file(cert_file, WOLFSSL_FILETYPE_PEM);
    if (cert == NULL) {
        return WOLFSSL_FAILURE;
    }

    cert_der = wolfSSL_X509_get_der(cert, &cert_der_sz);
    if (cert_der == NULL || cert_der_sz <= 0) {
        goto cleanup;
    }

    InitDecodedCert(&decoded, cert_der, (word32)cert_der_sz, NULL);
    decoded_init = 1;
    if (ParseCert(&decoded, CERT_TYPE, NO_VERIFY, NULL) != 0) {
        goto cleanup;
    }

    if (decoded.extSapkiSet && decoded.sapkiDer != NULL && decoded.sapkiLen > 0) {
        if (wolfSSL_X509_get_pubkey_buffer(cert, ecc_pubkey_buf, &ecc_pubkey_sz) != WOLFSSL_SUCCESS ||
            ecc_pubkey_sz <= 0) {
            goto cleanup;
        }
        alt_pubkey_info_sz = decoded.sapkiLen;
        if ((size_t)ecc_pubkey_sz > out_sz ||
            (size_t)alt_pubkey_info_sz > out_sz - (size_t)ecc_pubkey_sz ||
            (size_t)ecc_pubkey_sz + (size_t)alt_pubkey_info_sz > MAX_COMBINED_KEY_SZ) {
            goto cleanup;
        }
        /* Hybrid cert: concatenate ECC||Dilithium for Java byte[]. */
        memcpy(out, ecc_pubkey_buf, (size_t)ecc_pubkey_sz);
        memcpy(out + ecc_pubkey_sz, decoded.sapkiDer, (size_t)alt_pubkey_info_sz);
        *out_len = (size_t)ecc_pubkey_sz + (size_t)alt_pubkey_info_sz;
    } else if (decoded.publicKey != NULL && decoded.pubKeySize > 0) {
        if ((size_t)decoded.pubKeySize > out_sz) {
            goto cleanup;
        }
        /* Pure PQC cert (e.g. CertGenerator client bundle). */
        memcpy(out, decoded.publicKey, (size_t)decoded.pubKeySize);
        *out_len = (size_t)decoded.pubKeySize;
    }

cleanup:
    if (decoded_init) {
        FreeDecodedCert(&decoded);
    }
    if (cert != NULL) {
        wolfSSL_X509_free(cert);
    }
    return (*out_len > 0) ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}

static int encode_base64_no_nl(const unsigned char* input,
                               size_t input_len,
                               char* out_b64,
                               size_t out_b64_sz,
                               size_t* out_len)
{
    word32 b64_len;
    if (input == NULL || out_b64 == NULL || out_len == NULL) {
        return WOLFSSL_FAILURE;
    }
    b64_len = (word32)out_b64_sz;
    if (Base64_Encode_NoNl(input, (word32)input_len, (unsigned char*)out_b64, &b64_len) != 0 ||
        b64_len == 0 || b64_len > out_b64_sz) {
        return WOLFSSL_FAILURE;
    }
    *out_len = (size_t)b64_len;
    return WOLFSSL_SUCCESS;
}

static int send_server_key_payload_json(WOLFSSL* ssl)
{
    enum {
        MAX_B64_SZ = ((MAX_PUBKEY_DER_SZ + 2) / 3) * 4
    };
    unsigned char selected_key[MAX_PUBKEY_DER_SZ];
    unsigned char friend_key[MAX_PUBKEY_DER_SZ];
    size_t selected_key_sz = 0;
    size_t friend_key_sz = 0;
    char selected_key_b64[MAX_B64_SZ];
    char friend_key_b64[MAX_B64_SZ];
    size_t selected_key_b64_sz = 0;
    size_t friend_key_b64_sz = 0;

    if (ssl == NULL) {
        return WOLFSSL_FAILURE;
    }
    if (read_public_key_from_cert(CLIENT_CERT_FILE, selected_key, sizeof(selected_key), &selected_key_sz) != WOLFSSL_SUCCESS ||
        read_public_key_from_cert(FRIEND_CERT_FILE, friend_key, sizeof(friend_key), &friend_key_sz) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }
    if (encode_base64_no_nl(selected_key, selected_key_sz, selected_key_b64, sizeof(selected_key_b64), &selected_key_b64_sz) != WOLFSSL_SUCCESS ||
        encode_base64_no_nl(friend_key, friend_key_sz, friend_key_b64, sizeof(friend_key_b64), &friend_key_b64_sz) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    if (TLS_WRITE_LITERAL(ssl, "{\"clientpublickey\":\"") != WOLFSSL_SUCCESS ||
        tls_write_all(ssl, selected_key_b64, selected_key_b64_sz) != WOLFSSL_SUCCESS ||
        TLS_WRITE_LITERAL(ssl, "\",\"array\":[{\"secondPartyKey\":\"") != WOLFSSL_SUCCESS ||
        tls_write_all(ssl, friend_key_b64, friend_key_b64_sz) != WOLFSSL_SUCCESS ||
        TLS_WRITE_LITERAL(ssl, "\",\"nickname\":\"Alice\"}]}") != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}

 int main(int argc, char** argv) {
     int                 sockfd = -1;
     char                port_str[6];
     struct addrinfo     hints;
     struct addrinfo*    addr_list = NULL;
     struct addrinfo*    addr = NULL;
     WOLFSSL_CTX* ctx = NULL;
     WOLFSSL* ssl = NULL;
     char                msg[1024];
     int                 msgSz;
     const char*         server_addr = SERVER_IP;
     int                 server_port = SERVER_PORT;
     char*               port_end = NULL;
     long                parsed_port;
     int                 gai_rc;
     int                 connected = 0;

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
     if (!credential_files_readable()) {
         fprintf(stderr, "Failed to resolve cert paths.\n");
         fprintf(stderr, "Expected:\n");
         fprintf(stderr, "  %s\n", CLIENT_CERT_FILE);
         fprintf(stderr, "  %s\n", CLIENT_KEY_FILE);
         fprintf(stderr, "  %s\n", CA_CERT_FILE);
         fprintf(stderr, "  %s\n", FRIEND_CERT_FILE);
         fprintf(stderr, "Generate with CertGenerator option 3 in JAVA_TLS_TEST.\n");
         return EXIT_FAILURE;
     }
     printf("Using client credentials from %s\n", CLIENT_CERT_FILE);
 
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
 
     snprintf(port_str, sizeof(port_str), "%d", server_port);
     memset(&hints, 0, sizeof(hints));
     hints.ai_socktype = SOCK_STREAM;
     hints.ai_family = AF_UNSPEC;
     gai_rc = getaddrinfo(server_addr, port_str, &hints, &addr_list);
     if (gai_rc != 0) {
         fprintf(stderr, "Address resolution failed for '%s:%s': %s\n",
             server_addr, port_str, gai_strerror(gai_rc));
         return EXIT_FAILURE;
     }
 
     printf("Connecting to %s:%d...\n", server_addr, server_port);
     for (addr = addr_list; addr != NULL; addr = addr->ai_next) {
         sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
         if (sockfd < 0) {
             continue;
         }
         if (connect(sockfd, addr->ai_addr, addr->ai_addrlen) == 0) {
             connected = 1;
             break;
         }
         close(sockfd);
         sockfd = -1;
     }
     freeaddrinfo(addr_list);
     if (!connected) {
         err_sys("connect failed");
     }
 
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

  if (send_server_key_payload_json(ssl) != WOLFSSL_SUCCESS) {
       fprintf(stderr, "Error: Failed to send JSON payload.\n");
       fail_handshake_cleanup(ssl, ctx, sockfd);
   }
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
