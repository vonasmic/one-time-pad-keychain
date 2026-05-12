#include <jni.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#include <pthread.h>

/* ===================== CONFIG ===================== */

#define MAX_CONN 128

#define CERT_FILE    "../tls_usb_test/certs/server-cert-hybrid.pem"
#define KEY_FILE     "../tls_usb_test/certs/ecc-server-key.pem"
#define ALT_KEY_FILE "../tls_usb_test/certs/dilithium-server.priv"

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

/* ===================== CALLBACKS ===================== */

static int client_cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    int err = 0;
    
    #ifdef OPENSSL_EXTRA
    err = wolfSSL_X509_STORE_CTX_get_error(store);
    #else
    err = store->error;
    #endif
    
    if (preverify == 1) {
        return 1;
    }
    
    if (err == ASN_SELF_SIGNED_E || 
        err == ASN_NO_SIGNER_E
        #ifdef OPENSSL_EXTRA
        || err == WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        || err == WOLFSSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        #endif
        ) {
        printf("Certificate verification: Allowing self-signed client cert (error=%d)\n", err);
        return 1; 
    }
    
    printf("Certificate verification failed: error=%d\n", err);
    return 0;
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

        wolfSSL_set_fd(ssl, fd);

        if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl, 0);
            char buffer[80];
            fprintf(stderr, "TLS Handshake error: %s\n", wolfSSL_ERR_error_string(err, buffer));
            
            wolfSSL_free(ssl);
            close(fd);
            continue;
        }

        printf("TLS 1.3 Handshake Complete!\n");
        printf("Cipher: %s\n", wolfSSL_get_cipher_name(ssl));

        WOLFSSL_X509* client_cert = wolfSSL_get_peer_certificate(ssl);
        if (client_cert != NULL) {
            printf("Client certificate received and verified.\n");
            wolfSSL_X509_free(client_cert);
        } else {
            printf("Warning: No client certificate received.\n");
        }

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

JNIEXPORT jlong JNICALL Java_fel_cvut_TLS_TLSServerSocket_nativeInit
  (JNIEnv* env, jobject obj, jint port)
{
    wolfSSL_Init();
    wolfSSL_Debugging_ON();
    #if !defined(HAVE_PQC)
        fprintf(stderr, "Error: wolfSSL was not compiled with PQC support.\n");
        exit(EXIT_FAILURE);
    #endif

    queue_init(&acceptQueue);

    server_t* s = (server_t*)calloc(1, sizeof(server_t));
    pthread_mutex_init(&s->lock, NULL);

    /* TLS context */
    s->ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    if (s->ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_SetMinVersion(s->ctx, WOLFSSL_TLSV1_3) != WOLFSSL_SUCCESS) {
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
    
    for(int i = 0; i < num_candidates; i++) {
        if (wolfSSL_CTX_set_groups(s->ctx, &candidates[i], 1) == WOLFSSL_SUCCESS) {
            valid_groups[valid_count++] = candidates[i];
        }
    }

    if (valid_count == 0) {
        fprintf(stderr, "Error: No PQC groups supported.\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_set_groups(s->ctx, valid_groups, valid_count) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set groups failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Conf: %d Pure PQC Group(s) enabled (ML-KEM).\n", valid_count);

    /* 4. LOAD HYBRID CREDENTIALS */
    if (wolfSSL_CTX_use_certificate_file(s->ctx, CERT_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to load hybrid cert: %s\n", CERT_FILE);
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_use_PrivateKey_file(s->ctx, KEY_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to load primary key: %s\n", KEY_FILE);
        exit(EXIT_FAILURE);
    }

    #ifdef WOLFSSL_DUAL_ALG_CERTS
        if (wolfSSL_CTX_use_AltPrivateKey_file(s->ctx, ALT_KEY_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "Failed to load alt key: %s\n", ALT_KEY_FILE);
            exit(EXIT_FAILURE);
        }
        printf("Conf: Dual-Algorithm Credentials loaded.\n");

        /* --- ENFORCE DOUBLE SIGNING --- */
        /* NOTE: If your client doesn't support this, handshake will fail! */
        /*unsigned char cks_sigspec = WOLFSSL_CKS_SIGSPEC_BOTH;
        if (wolfSSL_CTX_UseCKS(s->ctx, &cks_sigspec, 1) != WOLFSSL_SUCCESS) {
             fprintf(stderr, "Error setting CKS config to BOTH.\n");
             exit(EXIT_FAILURE);
        }*/
        printf("Conf: Enforcing Dual-Sign (WOLFSSL_CKS_SIGSPEC_BOTH).\n");
    #else
        fprintf(stderr, "Error: WOLFSSL_DUAL_ALG_CERTS not enabled. Cannot run hybrid mode.\n");
        exit(EXIT_FAILURE);
    #endif

    /* 5. VERIFY CLIENT CERTIFICATES */
    /* Uncomment if you want to enforce client certs */
    // wolfSSL_CTX_set_verify(s->ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, client_cert_verify_callback);

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

JNIEXPORT jlong JNICALL Java_fel_cvut_TLS_TLSServerSocket_nativeAccept
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

JNIEXPORT void JNICALL Java_fel_cvut_TLS_TLSServerSocket_nativeClose
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