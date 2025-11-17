# Compiler
CC=gcc

# --- Paths ---
# Define the path to your local wolfssl git clone
WOLFSSL_DIR = ../wolfssl

# Path to the compiled static library (try multiple possible locations)
WOLFSSL_LIB_STATIC = $(WOLFSSL_DIR)/src/.libs/libwolfssl.a
WOLFSSL_LIB_SHARED = $(WOLFSSL_DIR)/src/.libs/libwolfssl.so

# --- Flags ---
# Compiler flags:
# Prefer system-installed wolfSSL (usually has dual-algorithm support)
# Fall back to local build if system library not available
# -g adds debug symbols
INCLUDE_APP = -I../app
# Add wolfssl source directory for internal.h access
CFLAGS = -g -Wall -I/usr/local/include/wolfssl -I$(WOLFSSL_DIR)/wolfssl $(INCLUDE_APP)

# Linker flags:
# Prefer system-installed library (usually has WOLFSSL_DUAL_ALG_CERTS enabled)
# Fall back to local build if needed
# We also need -lm for the math library, which wolfSSL depends on.
# On some systems, you may need -lpthread for threading support
LDFLAGS = -L/usr/local/lib -lwolfssl -lm -lpthread

# Target executable name
TARGET=tls_server
CLIENT_TARGET=tls_client
DUAL_SIGN_TARGET=dual_sign_test

all: $(TARGET) $(CLIENT_TARGET)

$(TARGET): tls_server.c
	@echo "Building TLS server..."
	@if [ ! -f $(WOLFSSL_LIB_STATIC) ] && [ ! -f $(WOLFSSL_LIB_SHARED) ]; then \
		echo "Warning: wolfSSL library not found in expected location."; \
		echo "Attempting to build with system-installed wolfSSL..."; \
	fi
	$(CC) $(CFLAGS) -DWOLFSSL_DUAL_ALG_CERTS -o $(TARGET) tls_server.c $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

$(CLIENT_TARGET): tls_client.c
	@echo "Building TLS client..."
	@if [ ! -f $(WOLFSSL_LIB_STATIC) ] && [ ! -f $(WOLFSSL_LIB_SHARED) ]; then \
		echo "Warning: wolfSSL library not found in expected location."; \
		echo "Attempting to build with system-installed wolfSSL..."; \
	fi
	$(CC) $(CFLAGS) -DWOLFSSL_DUAL_ALG_CERTS -o $(CLIENT_TARGET) tls_client.c $(LDFLAGS)
	@echo "Build complete: $(CLIENT_TARGET)"

clean:
	rm -f $(TARGET) $(CLIENT_TARGET) $(DUAL_SIGN_TARGET) *.o

.PHONY: all clean $(CLIENT_TARGET) $(DUAL_SIGN_TARGET)
