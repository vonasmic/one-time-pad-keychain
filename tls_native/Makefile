CC = gcc
# Prefer the repo wolfSSL build (supports standalone ML-KEM768 for JAVA_TLS_TEST).
WOLFSSL_DIR ?= ../wolfssl
WOLFSSL_CONFIG ?= wolfssl-config
WOLFSSL_CFLAGS = -g -Wall -I$(WOLFSSL_DIR)/wolfssl
WOLFSSL_LDFLAGS = -L$(WOLFSSL_DIR)/src/.libs -Wl,-rpath,$(abspath $(WOLFSSL_DIR)/src/.libs) -lwolfssl -lpthread -lm

# Use repo wolfSSL when the local library is present.
ifneq (,$(wildcard $(WOLFSSL_DIR)/src/.libs/libwolfssl.so))
CFLAGS = $(WOLFSSL_CFLAGS)
LDFLAGS = $(WOLFSSL_LDFLAGS)
else
CFLAGS = -g -Wall $(shell $(WOLFSSL_CONFIG) --cflags)
LDFLAGS = $(shell $(WOLFSSL_CONFIG) --libs) -lm
endif

TARGET=tls_server
CLIENT_TARGET=tls_client
JSON_CLIENT_TARGET=tls_client_json_payload

all: $(TARGET) $(CLIENT_TARGET) $(JSON_CLIENT_TARGET)

certs-native:
	@bash gen_native_certs.sh

certs-client: certs-native

$(TARGET): tls_server.c
	@echo "Building TLS server..."
	$(CC) $(CFLAGS) -o $(TARGET) tls_server.c $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

$(CLIENT_TARGET): tls_client.c
	@echo "Building TLS client..."
	$(CC) $(CFLAGS) -o $(CLIENT_TARGET) tls_client.c $(LDFLAGS)
	@echo "Build complete: $(CLIENT_TARGET)"

$(JSON_CLIENT_TARGET): tls_client_json_payload.c
	@echo "Building TLS JSON payload client..."
	$(CC) $(CFLAGS) -o $(JSON_CLIENT_TARGET) tls_client_json_payload.c $(LDFLAGS)
	@echo "Build complete: $(JSON_CLIENT_TARGET)"

clean:
	rm -f $(TARGET) $(CLIENT_TARGET) $(JSON_CLIENT_TARGET) *.o

.PHONY: all clean certs-native certs-client
