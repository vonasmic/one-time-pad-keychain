#ifndef OQS_OQSCONFIG_H
#define OQS_OQSCONFIG_H

// Minimal config for in-tree compilation
// Full config would come from liboqs build system

// Define that we're compiling (not using pre-built library)
#define OQS_DIST_BUILD

// Minimal common.h compatibility
#define OQS_MEM_malloc(x) malloc(x)
#define OQS_MEM_free(p) free(p)

#endif // OQS_OQSCONFIG_H

