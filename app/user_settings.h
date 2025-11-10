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

/* Platform */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SIZEOF_LONG_LONG 8
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_DEV_RANDOM
#define NO_OLD_TLS

/* Network I/O - disable socket support for embedded system */
#define WOLFSSL_USER_IO
#define WOLFSSL_NO_SOCK


/* Threading - disable for single-threaded embedded system */
#define SINGLE_THREADED

/* STM32U535 platform hints */
#define WOLFSSL_STM32U5
#define STM32_HAL_V2
#define WOLFSSL_STM32_CUBEMX

/* TLS 1.3 */
#define WOLFSSL_TLS13
#define HAVE_HKDF
/* TLS 1.3 requires AEAD (Authenticated Encryption with Associated Data) */
#define HAVE_AEAD
/* Disable legacy algorithms we don't use to reduce code size */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD5

/* Experimental settings for PQC */
#define WOLFSSL_EXPERIMENTAL_SETTINGS

/* Enable ML-KEM (Kyber / ML-KEM) */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM

/* SHA3/SHAKE required by ML-KEM */
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* Enable ECC for TLS cipher suites (used for certs and/or hybrid KEX) */
#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_ECC256
/* Single-precision ECC acceleration */
#define WOLFSSL_HAVE_SP_ECC

/* Timing resistance - CRITICAL for side-channel attack prevention */
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* Single Precision math optimized for Cortex-M */
#define WOLFSSL_SP
#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#define SP_WORD_SIZE 32

/* Memory optimization */
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_STACK_CACHE

/* TLS extensions (commonly used) */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES  /* Required for wolfSSL_UseKeyShare */
#define HAVE_SNI

/* Logging (optional for debugging)
 * Enable both lines to turn on debug prints at runtime.
 * //#define DEBUG_WOLFSSL
 */

#endif /* USER_SETTINGS_H */


