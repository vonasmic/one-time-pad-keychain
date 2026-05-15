#ifndef TLS_HYBRID_VERIFY_H
#define TLS_HYBRID_VERIFY_H

#include <stdio.h>
#include <wolfssl/ssl.h>

#ifdef WOLFSSL_DUAL_ALG_CERTS
#include <internal.h>
#endif

static int tls_verify_peer_cert(WOLFSSL* ssl)
{
    long result = wolfSSL_get_verify_result(ssl);

    if (result != WOLFSSL_X509_V_OK) {
        fprintf(stderr,
            "Error: Peer certificate verification failed (result=%ld).\n",
            result);
        return 0;
    }
    return 1;
}

#ifdef WOLFSSL_DUAL_ALG_CERTS

static int tls_require_peer_dual_alt_sig(WOLFSSL* ssl)
{
    if (ssl->peerSigSpec == NULL || ssl->peerSigSpecSz == 0) {
        fprintf(stderr,
            "Error: peer did not send CKS; dual alt signature was not used.\n");
        return 0;
    }

    if (ssl->peerSigSpec[0] != WOLFSSL_CKS_SIGSPEC_BOTH) {
        fprintf(stderr,
            "Error: peer CKS is not BOTH (got %u).\n",
            (unsigned)ssl->peerSigSpec[0]);
        return 0;
    }

    return 1;
}

static int tls_require_local_dual_alt_sig(WOLFSSL* ssl)
{
    if (ssl->sigSpec == NULL || ssl->sigSpecSz == 0) {
        fprintf(stderr,
            "Error: local CKS not set; dual alt signature was not used.\n");
        return 0;
    }

    if (ssl->sigSpec[0] != WOLFSSL_CKS_SIGSPEC_BOTH) {
        fprintf(stderr,
            "Error: negotiated local CKS is not BOTH (got %u).\n",
            (unsigned)ssl->sigSpec[0]);
        return 0;
    }

    if (ssl->buffers.altKey == NULL) {
        fprintf(stderr,
            "Error: BOTH negotiated but alt private key is missing.\n");
        return 0;
    }

    return 1;
}

#endif /* WOLFSSL_DUAL_ALG_CERTS */

#endif /* TLS_HYBRID_VERIFY_H */
