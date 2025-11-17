#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* Include STM32 device and HAL headers before wolfSSL processes STM32 port header */
/* This ensures CRYP_HandleTypeDef and HAL CRYP functions are available when present */
#include "stm32u5xx.h"
#include "stm32u5xx_hal_conf.h"

/* Conditionally enable CRYP acceleration only if AES peripheral exists on this part */
#ifdef AES
#ifndef HAL_CRYP_MODULE_ENABLED
#define HAL_CRYP_MODULE_ENABLED
#endif
#include "stm32u5xx_hal_cryp.h"
#else
/* If no AES peripheral, disable wolfSSL STM32 CRYPTO path to avoid build errors */
#ifndef NO_STM32_CRYPTO
#define NO_STM32_CRYPTO
#endif
#endif

/* Time handling for wolfSSL */
/* Use wolfSSL's own struct tm definition to ensure it's available early */
/* This is needed because asn_public.h declares functions with struct tm* before struct tm is defined */
/* Note: We don't define USE_WOLF_TIME_T because the standard library already provides time_t */
#define USE_WOLF_TM
/* Use wolfSSL's gmtime implementation (required when USE_WOLF_TM is defined) */
#define WOLFSSL_GMTIME
/* Use wolfSSL's date validation to avoid needing mktime from standard library */
#define USE_WOLF_VALIDDATE

/* Platform */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SIZEOF_LONG_LONG 8
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_DEV_RANDOM
#define NO_OLD_TLS

/* Network I/O - disable socket support for embedded system */
#define WOLFSSL_USER_IO
#define NO_WRITEV
#define WOLFSSL_NO_SOCK


/* Threading - disable for single-threaded embedded system */
#define SINGLE_THREADED

/* Trim wolfSSL feature set for client-only firmware to reduce flash size */
#define NO_WOLFSSL_SERVER           /* drop server handshake/state machines */
#define NO_SESSION_CACHE            /* disable session resumption cache */
#define WOLFSSL_NO_TLS12            /* build TLS 1.3 only to shrink ssl.c */
#ifdef HAVE_SESSION_TICKET
#undef HAVE_SESSION_TICKET          /* avoid pulling in TLS ticket machinery */
#endif

/* STM32U535 platform hints */
#define WOLFSSL_STM32U5
#define STM32_HAL_V2
#define WOLFSSL_STM32_CUBEMX
/* Use default STM32 hardware RNG for secure random number generation */
#define STM32_RNG
#define CUSTOM_RAND_GENERATE_SEED_OS  custom_wc_GenerateSeed

/* TLS 1.3 */
#define WOLFSSL_TLS13
#define HAVE_HKDF
/* TLS 1.3 requires AEAD (Authenticated Encryption with Associated Data) */
#define HAVE_AEAD
/* Enable AES-GCM cipher suites (TLS_AES_128/256_GCM_SHA256/384) */
#define HAVE_AES
#define HAVE_AESGCM
#define WOLFSSL_AES_GCM
/* Explicitly enable AES-256 and SHA-384 for TLS13-AES256-GCM-SHA384 cipher suite */
#define WOLFSSL_AES_256
#define WOLFSSL_SHA384
/* Enable required hash algorithms for TLS 1.3 suites */
#define HAVE_SHA256
#define HAVE_SHA384
/* Enable dual-algorithm certificates for true hybrid PQC */
/* This requires both ECC and Dilithium signatures simultaneously */
/* If one algorithm fails, the other still provides security */
/* Note: Requires WOLFSSL_ASN_TEMPLATE (enabled by default) */
/* Note: WOLFSSL_DUAL_ALG_CERTS requires RSA support (even if not used) */
#define WOLFSSL_DUAL_ALG_CERTS


/* RSA-PSS support (required for TLS 1.3 with RSA) */
#ifdef WOLFSSL_TLS13
#define HAVE_RSA
#define WC_RSA_PSS
#endif

#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD5
#define NO_MD4  /* Disable MD4 (legacy, not needed for TLS 1.3) */

/* Experimental settings for PQC */
#define WOLFSSL_EXPERIMENTAL_SETTINGS

/* Enable ML-KEM (Kyber / ML-KEM) */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_ML_KEM_LEVEL 3

/* SHA3/SHAKE required by ML-KEM */
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* Enable Dilithium (ML-DSA) for hybrid signatures */
#define HAVE_DILITHIUM
#define WOLFSSL_HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define WOLFSSL_DILITHIUM_LEVEL 3

/* CRITICAL: Enable OID support so the client can read the headers */
#define HAVE_OID_ENCODING
#define HAVE_OID_DECODING
#define WOLFSSL_CUSTOM_OID
#define WOLFSSL_WC_DILITHIUM
/* Memory optimizations for embedded system */
#define WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM  /* Smaller memory for verification */
#define WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC  /* Use fixed buffers, no malloc */
#define WOLFSSL_DILITHIUM_NO_MAKE_KEY       /* Client doesn't generate keys */
/* Note: Client needs to sign, so WOLFSSL_DILITHIUM_NO_SIGN is NOT set */
/* WOLFSSL_DUAL_ALG_CERTS automatically enables:
 *   - WOLFSSL_CERT_GEN
 *   - WOLFSSL_CUSTOM_OID
 *   - HAVE_OID_ENCODING
 *   - WOLFSSL_CERT_EXT
 *   - OPENSSL_EXTRA (already enabled)
 *   - HAVE_OID_DECODING
 */

/* Enable ECC for TLS cipher suites (used for certs and/or hybrid KEX) */
#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_ECC256
#define HAVE_ECC384  /* Required for WOLFSSL_ECC_SECP384R1 group */
/* Single-precision ECC acceleration (disabled to save ~45 KiB flash) */
//#define WOLFSSL_HAVE_SP_ECC

/* Timing resistance - CRITICAL for side-channel attack prevention */
#define ECC_TIMING_RESISTANT
/* RSA enabled for WOLFSSL_DUAL_ALG_CERTS support (required even if using ECC+Dilithium) */
#define WC_RSA_BLINDING  /* Enable RSA blinding to prevent timing attacks */

/* Single Precision math optimized for Cortex-M (disabled to reduce footprint) */
/* #define WOLFSSL_SP */
/* #define WOLFSSL_SP_ARM_CORTEX_M_ASM */ 
/* Force 32-bit word size for ARM Cortex-M (32-bit architecture) */
/* #define SP_WORD_SIZE 32 */
/* Disable 128-bit integer support (not available on ARM Cortex-M33) */
#define NO_INT128
#define SP_INT_BITS 2048

/* Memory optimization */
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_STACK_CACHE

/* TLS buffer sizes - CRITICAL for PQC algorithms */
/* PQC algorithms (ML-KEM, Dilithium) require large TLS record buffers */
/* ML-KEM-768 public keys are ~1184 bytes, ciphertexts ~1088 bytes */
/* Default RECORD_SIZE (128 bytes) is too small for PQC handshakes */
#define LARGE_STATIC_BUFFERS  /* Enable 16KB record buffers (max TLS standard allows) */

/* TLS extensions (commonly used) */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES  /* Required for wolfSSL_UseKeyShare */
/* SNI disabled - not used in this client implementation */
/* #define HAVE_SNI */

/* Enable OpenSSL-compatible API for signature algorithm configuration */
#define OPENSSL_EXTRA  /* Required for wolfSSL_set1_sigalgs_list */

/* Keep session certificate chains so wolfSSL_get_peer_chain is available */
#define SESSION_CERTS

//#define DEBUG_WOLFSSL
/* Logging (optional for debugging)
 * Enable both lines to turn on debug prints at runtime.
 */

/* Enable wolfSSL diagnostics queue to capture debug logs during TLS handshake */
#ifndef TLS_DIAG_QUEUE_ENABLED
//#define TLS_DIAG_QUEUE_ENABLED
#endif

#endif /* USER_SETTINGS_H */


