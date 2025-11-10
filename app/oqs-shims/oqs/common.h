#ifndef OQS_COMMON_H
#define OQS_COMMON_H

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../oqsconfig.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Minimal compatibility with liboqs common.h
// OQS_API macro for exported functions
#ifndef OQS_API
#ifdef OQS_BUILDING
#define OQS_API
#else
#define OQS_API
#endif
#endif

#if defined(__cplusplus)
} // extern "C"
#endif

#endif // OQS_COMMON_H

