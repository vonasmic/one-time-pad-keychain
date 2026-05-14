#include <jni.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#if defined(WOLFSSL_DUAL_ALG_CERTS)
#include <internal.h>
#include <pthread.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static byte s_ctxSigSpec[1];

#if defined(WOLFSSL_DUAL_ALG_CERTS)
#define MAX_TRACKED_VERIFY_CBS 128

typedef struct verify_cb_entry {
    WOLFSSL* ssl;
    VerifyCallback previous_cb;
} verify_cb_entry;

static verify_cb_entry s_verify_cb_entries[MAX_TRACKED_VERIFY_CBS];
static pthread_mutex_t s_verify_cb_lock = PTHREAD_MUTEX_INITIALIZER;

static int find_verify_cb_entry_index(WOLFSSL* ssl)
{
    int i;

    for (i = 0; i < MAX_TRACKED_VERIFY_CBS; i++) {
        if (s_verify_cb_entries[i].ssl == ssl) {
            return i;
        }
    }

    return -1;
}

static int find_empty_verify_cb_entry_index(void)
{
    int i;

    for (i = 0; i < MAX_TRACKED_VERIFY_CBS; i++) {
        if (s_verify_cb_entries[i].ssl == NULL) {
            return i;
        }
    }

    return -1;
}

static int track_previous_verify_callback(WOLFSSL* ssl, VerifyCallback cb)
{
    int idx;

    if (ssl == NULL) {
        return 0;
    }

    pthread_mutex_lock(&s_verify_cb_lock);

    idx = find_verify_cb_entry_index(ssl);
    if (idx < 0) {
        idx = find_empty_verify_cb_entry_index();
    }

    if (idx < 0) {
        pthread_mutex_unlock(&s_verify_cb_lock);
        return 0;
    }

    s_verify_cb_entries[idx].ssl = ssl;
    s_verify_cb_entries[idx].previous_cb = cb;

    pthread_mutex_unlock(&s_verify_cb_lock);
    return 1;
}

static VerifyCallback get_tracked_previous_verify_callback(WOLFSSL* ssl)
{
    int idx;
    VerifyCallback cb = NULL;

    if (ssl == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&s_verify_cb_lock);

    idx = find_verify_cb_entry_index(ssl);
    if (idx >= 0) {
        cb = s_verify_cb_entries[idx].previous_cb;
    }

    pthread_mutex_unlock(&s_verify_cb_lock);
    return cb;
}

static WOLFSSL* resolve_ssl_from_store_ctx(WOLFSSL_X509_STORE_CTX* store)
{
    int exDataIdx;

    if (store == NULL) {
        return NULL;
    }

#if !defined(OPENSSL_EXTRA) && !defined(WOLFSSL_WPAS_SMALL)
    return NULL;
#else
    exDataIdx = wolfSSL_get_ex_data_X509_STORE_CTX_idx();
    if (exDataIdx < 0) {
        return NULL;
    }

    return (WOLFSSL*)wolfSSL_X509_STORE_CTX_get_ex_data(store, exDataIdx);
#endif
}

static jboolean dual_alg_cks_both_negotiated(WOLFSSL* ssl)
{
    if (ssl == NULL || ssl->peerSigSpec == NULL || ssl->sigSpec == NULL) {
        return JNI_FALSE;
    }
    if (ssl->peerSigSpecSz == 0 || ssl->sigSpecSz == 0) {
        return JNI_FALSE;
    }

    if (*ssl->peerSigSpec != WOLFSSL_CKS_SIGSPEC_BOTH ||
        *ssl->sigSpec != WOLFSSL_CKS_SIGSPEC_BOTH) {
        return JNI_FALSE;
    }

    if (ssl->buffers.altKey == NULL) {
        return JNI_FALSE;
    }

    if (wolfSSL_is_init_finished(ssl) && wolfSSL_is_server(ssl)) {
        if (!ssl->options.havePeerVerify || !ssl->options.peerAuthGood) {
            return JNI_FALSE;
        }
    }

    return JNI_TRUE;
}

static int dual_sign_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    WOLFSSL* ssl;
    VerifyCallback previousCb;
    int delegated;

    ssl = resolve_ssl_from_store_ctx(store);
    if (ssl == NULL) {
        return 0;
    }

    previousCb = get_tracked_previous_verify_callback(ssl);
    if (previousCb != NULL && previousCb != dual_sign_verify_cb) {
        delegated = previousCb(preverify, store);
        if (delegated != 1) {
            return delegated;
        }
    }
    else if (preverify != 1) {
        return 0;
    }

    return dual_alg_cks_both_negotiated(ssl) == JNI_TRUE ? 1 : 0;
}
#endif

static void throw_dual_sign_exception(JNIEnv* env, const char* message)
{
    jclass cls = (*env)->FindClass(env, "fel/cvut/TLS/WolfSslDualSignException");
    if (cls != NULL) {
        (*env)->ThrowNew(env, cls, message);
    }
}

JNIEXPORT void JNICALL Java_fel_cvut_TLS_WolfSslDualSign_nativeConfigureServerDualSign
  (JNIEnv* env, jclass clazz, jlong ctxPtr, jstring altPrivateKeyPath, jint sigSpec)
{
    WOLFSSL_CTX* ctx;
    const char* altKeyPath;
    char errBuf[256];

    (void)clazz;

    if (ctxPtr == 0) {
        throw_dual_sign_exception(env, "WOLFSSL_CTX pointer is null");
        return;
    }

    ctx = (WOLFSSL_CTX*)(uintptr_t)ctxPtr;

#ifndef WOLFSSL_DUAL_ALG_CERTS
    throw_dual_sign_exception(env,
        "wolfSSL was not built with WOLFSSL_DUAL_ALG_CERTS");
    return;
#else
    if (altPrivateKeyPath == NULL) {
        throw_dual_sign_exception(env, "Alternative private key path is null");
        return;
    }

    altKeyPath = (*env)->GetStringUTFChars(env, altPrivateKeyPath, NULL);
    if (altKeyPath == NULL) {
        return;
    }

    if (wolfSSL_CTX_use_AltPrivateKey_file(ctx, altKeyPath,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        snprintf(errBuf, sizeof(errBuf),
            "Failed to load alternative private key: %s", altKeyPath);
        (*env)->ReleaseStringUTFChars(env, altPrivateKeyPath, altKeyPath);
        throw_dual_sign_exception(env, errBuf);
        return;
    }

    (*env)->ReleaseStringUTFChars(env, altPrivateKeyPath, altKeyPath);

    s_ctxSigSpec[0] = (byte)sigSpec;
    if (wolfSSL_CTX_UseCKS(ctx, s_ctxSigSpec, sizeof(s_ctxSigSpec)) !=
            WOLFSSL_SUCCESS) {
        throw_dual_sign_exception(env,
            "Failed to configure server CKS signature spec");
    }
#endif
}

JNIEXPORT jboolean JNICALL
Java_fel_cvut_TLS_WolfSslDualSign_nativeIsDualSignatureNegotiated
  (JNIEnv* env, jclass clazz, jlong x509StorePtr)
{
    WOLFSSL_X509_STORE_CTX* store;
    WOLFSSL* ssl;

    (void)clazz;

    if (x509StorePtr == 0) {
        throw_dual_sign_exception(env, "WOLFSSL_X509_STORE_CTX pointer is null");
        return JNI_FALSE;
    }

#ifndef WOLFSSL_DUAL_ALG_CERTS
    throw_dual_sign_exception(env,
        "wolfSSL was not built with WOLFSSL_DUAL_ALG_CERTS");
    return JNI_FALSE;
#elif !defined(OPENSSL_EXTRA) && !defined(WOLFSSL_WPAS_SMALL)
    throw_dual_sign_exception(env,
        "wolfSSL was not built with OPENSSL_EXTRA/WOLFSSL_WPAS_SMALL for ex_data lookup");
    return JNI_FALSE;
#else
    store = (WOLFSSL_X509_STORE_CTX*)(uintptr_t)x509StorePtr;
    ssl = resolve_ssl_from_store_ctx(store);
    if (ssl == NULL) {
        throw_dual_sign_exception(env,
            "Failed to resolve WOLFSSL session from store context");
        return JNI_FALSE;
    }

    return dual_alg_cks_both_negotiated(ssl);
#endif
}

JNIEXPORT jboolean JNICALL
Java_fel_cvut_TLS_WolfSslDualSign_nativeIsDualSignatureNegotiatedOnSsl
  (JNIEnv* env, jclass clazz, jlong sslPtr)
{
    WOLFSSL* ssl;

    (void)clazz;

    if (sslPtr == 0) {
        throw_dual_sign_exception(env, "WOLFSSL pointer is null");
        return JNI_FALSE;
    }

#ifndef WOLFSSL_DUAL_ALG_CERTS
    throw_dual_sign_exception(env,
        "wolfSSL was not built with WOLFSSL_DUAL_ALG_CERTS");
    return JNI_FALSE;
#else
    ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    return dual_alg_cks_both_negotiated(ssl);
#endif
}

JNIEXPORT void JNICALL
Java_fel_cvut_TLS_WolfSslDualSign_nativeInstallDualSignVerifyOnSsl
  (JNIEnv* env, jclass clazz, jlong sslPtr, jint verifyMode)
{
    WOLFSSL* ssl;
    VerifyCallback currentCb;

    (void)clazz;

    if (sslPtr == 0) {
        throw_dual_sign_exception(env, "WOLFSSL pointer is null");
        return;
    }

#ifndef WOLFSSL_DUAL_ALG_CERTS
    throw_dual_sign_exception(env,
        "wolfSSL was not built with WOLFSSL_DUAL_ALG_CERTS");
    return;
#elif !defined(OPENSSL_EXTRA) && !defined(WOLFSSL_WPAS_SMALL)
    throw_dual_sign_exception(env,
        "wolfSSL was not built with OPENSSL_EXTRA/WOLFSSL_WPAS_SMALL for ex_data lookup");
    return;
#else
    ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    currentCb = wolfSSL_get_verify_callback(ssl);

    if (currentCb != dual_sign_verify_cb) {
        if (!track_previous_verify_callback(ssl, currentCb)) {
            throw_dual_sign_exception(env,
                "Failed to track previous verify callback");
            return;
        }
    }

    wolfSSL_set_verify(ssl, (int)verifyMode, dual_sign_verify_cb);
#endif
}
