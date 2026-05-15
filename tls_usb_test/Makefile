CC = gcc
WOLFSSL_CONFIG ?= wolfssl-config

# Installed wolfSSL: options.h + link flags come from wolfssl-config.
CFLAGS = -g -Wall $(shell $(WOLFSSL_CONFIG) --cflags)
LDFLAGS = $(shell $(WOLFSSL_CONFIG) --libs) -lm

# internal.h is not installed; client/server use it for CKS introspection.
WOLFSSL_SRC ?= ../wolfssl/wolfssl
NATIVE_TLS_DIR ?= ../JAVA_TLS_TEST/src/main/native_tls
INTERNAL_CFLAGS = $(CFLAGS) -I$(WOLFSSL_SRC) -I$(NATIVE_TLS_DIR)

TARGET=tls_server
CLIENT_TARGET=tls_client
DUAL_SIGN_TARGET=dual_sign_test

all: $(TARGET) $(CLIENT_TARGET)

certs-native:
	@bash gen_native_certs.sh

certs-client: certs-native

$(TARGET): tls_server.c
	@echo "Building TLS server..."
	$(CC) $(INTERNAL_CFLAGS) -o $(TARGET) tls_server.c $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

$(CLIENT_TARGET): tls_client.c
	@echo "Building TLS client..."
	$(CC) $(INTERNAL_CFLAGS) -o $(CLIENT_TARGET) tls_client.c $(LDFLAGS)
	@echo "Build complete: $(CLIENT_TARGET)"

clean:
	rm -f $(TARGET) $(CLIENT_TARGET) $(DUAL_SIGN_TARGET) *.o

.PHONY: all clean certs-native certs-client
