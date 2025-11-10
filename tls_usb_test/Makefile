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
# -I$(WOLFSSL_DIR) tells GCC to find headers (like wolfssl/ssl.h) in ../wolfssl
# -g adds debug symbols
CFLAGS = -g -Wall -I$(WOLFSSL_DIR)

# Linker flags:
# Try static library first, then shared library
# We also need -lm for the math library, which wolfSSL depends on.
# On some systems, you may need -lpthread for threading support
LDFLAGS = -L$(WOLFSSL_DIR)/src/.libs -lwolfssl -lm -lpthread

# Target executable name
TARGET=tls_server

all: $(TARGET)

$(TARGET): tls_server.c
	@echo "Building TLS server..."
	@if [ ! -f $(WOLFSSL_LIB_STATIC) ] && [ ! -f $(WOLFSSL_LIB_SHARED) ]; then \
		echo "Warning: wolfSSL library not found in expected location."; \
		echo "Attempting to build with system-installed wolfSSL..."; \
	fi
	$(CC) $(CFLAGS) -o $(TARGET) tls_server.c $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
