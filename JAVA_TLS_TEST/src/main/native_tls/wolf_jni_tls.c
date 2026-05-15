#include <jni.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include "tls_hybrid_verify.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#include <pthread.h>

/* ===================== CONFIG ===================== */

#define MAX_CONN 128

#define CERT_FILE    "certs/native/server/server-cert-hybrid.pem"
#define KEY_FILE     "certs/native/server/ecc-server-key.pem"
#define ALT_KEY_FILE "certs/native/server/dilithium-server.priv"
#define CA_CERT_FILE "certs/native/server/root-ca.pem"

static const byte server_cks_order[] = {
    WOLFSSL_CKS_SIGSPEC_BOTH,
};

static void print_native_cert_help(const char* label, const char* path)
{
    char cwd[512];

    fprintf(stderr, "%s: %s\n", label, path);
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        fprintf(stderr, "  Current working directory: %s\n", cwd);
    }
    if (access(path, F_OK) != 0) {
        fprintf(stderr, "  File does not exist (run cert generation first).\n");
    } else {
        fprintf(stderr, "  File is present but could not be loaded (check PEM format).\n");
    }
    fprintf(stderr, "  Generate native hybrid certs:\n");
    fprintf(stderr, "    cd tls_usb_test && ./gen_native_certs.sh\n");
    fprintf(stderr, "    # or: make certs-native\n");
    fprintf(stderr, "  Output: JAVA_TLS_TEST/certs/native/server/ and .../client/\n");
    fprintf(stderr, "  Start this server from JAVA_TLS_TEST/ (e.g. mvn exec:java on PQCJavaSideTls).\n");
}

/* ===================== STRUCTS ===================== */

typedef struct {
    int active;
    int fd;
    WOLFSSL* ssl;
} conn_t;

typedef struct {
    int sockfd;
    WOLFSSL_CTX* ctx;

    conn_t conns[MAX_CONN];

    pthread_t accept_thread;
    pthread_mutex_t lock;

    int running;
} server_t;

/* queue for accept() */
typedef struct node {
    int id;
    struct node* next;
} node_t;

typedef struct {
    node_t* head;
    node_t* tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} queue_t;

/* ===================== GLOBAL QUEUE ===================== */

static queue_t acceptQueue;

/* ===================== UTILS ===================== */

static void queue_init(queue_t* q) {
    q->head = q->tail = NULL;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
}

static void queue_push(int id) {
    node_t* n = (node_t*)malloc(sizeof(node_t));
    n->id = id;
    n->next = NULL;

    pthread_mutex_lock(&acceptQueue.mutex);

    if (acceptQueue.tail) {
        acceptQueue.tail->next = n;
    } else {
        acceptQueue.head = n;
    }

    acceptQueue.tail = n;
    pthread_cond_signal(&acceptQueue.cond);

    pthread_mutex_unlock(&acceptQueue.mutex);
}

static int queue_pop() {
    pthread_mutex_lock(&acceptQueue.mutex);

    while (acceptQueue.head == NULL) {
        pthread_cond_wait(&acceptQueue.cond, &acceptQueue.mutex);
    }

    node_t* n = acceptQueue.head;
    acceptQueue.head = n->next;
    if (!acceptQueue.head) acceptQueue.tail = NULL;

    pthread_mutex_unlock(&acceptQueue.mutex);

    int id = n->id;
    free(n);
    return id;
}

static void close_failed_handshake(WOLFSSL* ssl, int fd)
{
    if (ssl != NULL) {
        wolfSSL_free(ssl);
    }
    if (fd >= 0) {
        close(fd);
    }
}

/* ===================== ACCEPT THREAD ===================== */

static void* accept_loop(void* arg) {
    server_t* s = (server_t*)arg;

    struct sockaddr_in client;
    socklen_t len = sizeof(client);

    while (s->running) {

        int fd = accept(s->sockfd, (struct sockaddr*)&client, &len);
        if (fd < 0) continue;

        WOLFSSL* ssl = wolfSSL_new(s->ctx);
        if (ssl == NULL) {
            close(fd);
            continue;
        }

        if (wolfSSL_UseCKS(ssl, (byte*)server_cks_order,
                sizeof(server_cks_order)) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "Error setting per-connection CKS to BOTH.\n");
            wolfSSL_free(ssl);
            close(fd);
            continue;
        }

        wolfSSL_set_fd(ssl, fd);

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
                "  Hint: restart the JVM after ./gen_native_certs.sh (certs load once at startup).\n");
            fprintf(stderr,
                "  Trust anchor: %s\n", CA_CERT_FILE);
            close_failed_handshake(ssl, fd);
            continue;
        }

        printf("TLS 1.3 Handshake Complete!\n");
        printf("Cipher: %s\n", wolfSSL_get_cipher_name(ssl));

        if (!tls_verify_peer_cert(ssl)) {
            close_failed_handshake(ssl, fd);
            continue;
        }
        printf("Client certificate verified against %s.\n", CA_CERT_FILE);

        if (!tls_require_local_dual_alt_sig(ssl)) {
            close_failed_handshake(ssl, fd);
            continue;
        }
        if (!tls_require_peer_dual_alt_sig(ssl)) {
            close_failed_handshake(ssl, fd);
            continue;
        }
        printf("Dual alt signature (CKS BOTH) confirmed.\n");

        pthread_mutex_lock(&s->lock);

        for (int i = 0; i < MAX_CONN; i++) {
            if (!s->conns[i].active) {

                s->conns[i].active = 1;
                s->conns[i].fd = fd;
                s->conns[i].ssl = ssl;

                queue_push(i);

                break;
            }
        }

        pthread_mutex_unlock(&s->lock);
    }

    return NULL;
}

/* ===================== JNI EXPORTS ===================== */

/* Wrapping in extern "C" prevents name mangling errors in C++ compilers */
#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jlong JNICALL Java_fel_cvut_TLS_NativeTlsServer_nativeInit
  (JNIEnv* env, jobject obj, jint port)
{
    wolfSSL_Init();
    #if !defined(HAVE_PQC)
        fprintf(stderr, "Error: wolfSSL was not compiled with PQC support.\n");
        exit(EXIT_FAILURE);
    #endif

    queue_init(&acceptQueue);

    server_t* s = (server_t*)calloc(1, sizeof(server_t));
    pthread_mutex_init(&s->lock, NULL);

    /* TLS context */
    s->ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (s->ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_SetMinVersion(s->ctx, WOLFSSL_TLSV1_3) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error: Could not set minimum version to TLS 1.3\n");
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
        if (wolfSSL_CTX_set_groups(s->ctx, &candidates[i], 1) == WOLFSSL_SUCCESS) {
            valid_groups[valid_count++] = candidates[i];
        }
    }

    if (valid_count == 0) {
        fprintf(stderr,
            "Error: No supported ML-KEM groups. Use hybrid groups instead.\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_set_groups(s->ctx, valid_groups, valid_count) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set groups failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Conf: %d hybrid ML-KEM group(s) enabled.\n", valid_count);

    /* 4. LOAD HYBRID CREDENTIALS */
    if (wolfSSL_CTX_use_certificate_file(s->ctx, CERT_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        print_native_cert_help("Failed to load hybrid cert", CERT_FILE);
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_use_PrivateKey_file(s->ctx, KEY_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        print_native_cert_help("Failed to load primary key", KEY_FILE);
        exit(EXIT_FAILURE);
    }

    #ifdef WOLFSSL_DUAL_ALG_CERTS
        if (wolfSSL_CTX_use_AltPrivateKey_file(s->ctx, ALT_KEY_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
            print_native_cert_help("Failed to load alt key", ALT_KEY_FILE);
            exit(EXIT_FAILURE);
        }
        if (wolfSSL_CTX_UseCKS(s->ctx, (byte*)server_cks_order,
                sizeof(server_cks_order)) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "Error setting CKS config to BOTH.\n");
            exit(EXIT_FAILURE);
        }
        printf("Conf: Dual-Algorithm Credentials loaded.\n");
        printf("Conf: Enforcing Dual-Sign (WOLFSSL_CKS_SIGSPEC_BOTH).\n");
    #else
        fprintf(stderr, "Error: WOLFSSL_DUAL_ALG_CERTS not enabled. Cannot run hybrid mode.\n");
        exit(EXIT_FAILURE);
    #endif

    if (wolfSSL_CTX_load_verify_locations(s->ctx, CA_CERT_FILE, NULL) != WOLFSSL_SUCCESS) {
        print_native_cert_help("Error loading CA cert", CA_CERT_FILE);
        exit(EXIT_FAILURE);
    }

    wolfSSL_CTX_set_verify(s->ctx,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    printf("Conf: Client certificate authentication enabled (strict CA verification).\n");

    /* TCP socket */
    s->sockfd = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
    setsockopt(s->sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s->sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    listen(s->sockfd, 128);

    s->running = 1;

    pthread_create(&s->accept_thread, NULL, accept_loop, s);

    return (jlong)s;
}

JNIEXPORT jlong JNICALL Java_fel_cvut_TLS_NativeTlsServer_nativeAccept
  (JNIEnv* env, jobject obj, jlong handle)
{
    (void)handle;
    return queue_pop();
}

JNIEXPORT jbyteArray JNICALL Java_fel_cvut_TLS_TLSSocket_nativeRead
  (JNIEnv* env, jobject obj, jlong serverHandle, jlong connId)
{
    server_t* s = (server_t*)serverHandle;
    conn_t* c = &s->conns[connId];

    char buf[4096];

    int len = wolfSSL_read(c->ssl, buf, sizeof(buf));
    if (len <= 0) return NULL;

    jbyteArray out = (*env)->NewByteArray(env, len);
    (*env)->SetByteArrayRegion(env, out, 0, len, (jbyte*)buf);

    return out;
}

JNIEXPORT void JNICALL Java_fel_cvut_TLS_TLSSocket_nativeWrite
  (JNIEnv* env, jobject obj, jlong serverHandle, jlong connId, jbyteArray data)
{
    server_t* s = (server_t*)serverHandle;
    conn_t* c = &s->conns[connId];

    jbyte* buf = (*env)->GetByteArrayElements(env, data, NULL);
    jsize len = (*env)->GetArrayLength(env, data);

    wolfSSL_write(c->ssl, buf, len);

    (*env)->ReleaseByteArrayElements(env, data, buf, 0);
}

JNIEXPORT void JNICALL Java_fel_cvut_TLS_TLSSocket_nativeConnClose
  (JNIEnv* env, jobject obj, jlong serverHandle, jlong connId)
{
    server_t* s = (server_t*)serverHandle;
    conn_t* c = &s->conns[connId];

    if (c->active) {
        wolfSSL_shutdown(c->ssl);
        wolfSSL_free(c->ssl);
        close(c->fd);

        c->active = 0;
    }
}

JNIEXPORT void JNICALL Java_fel_cvut_TLS_NativeTlsServer_nativeClose
  (JNIEnv* env, jobject obj, jlong handle)
{
    server_t* s = (server_t*)handle;

    s->running = 0;

    /* Cancel the thread if needed, or close socket to unblock accept */
    close(s->sockfd);
    
    /* Small delay to allow thread to exit loop */
    usleep(10000); 

    for (int i = 0; i < MAX_CONN; i++) {
        if (s->conns[i].active) {
            wolfSSL_shutdown(s->conns[i].ssl);
            wolfSSL_free(s->conns[i].ssl);
            close(s->conns[i].fd);
        }
    }

    wolfSSL_CTX_free(s->ctx);
    wolfSSL_Cleanup();

    free(s);
}

#ifdef __cplusplus
}
#endif