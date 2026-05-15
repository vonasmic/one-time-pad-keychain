CC = gcc
WOLFSSL_CONFIG ?= wolfssl-config
JAVA_HOME ?= /usr/lib/jvm/java-21-openjdk-amd64

CFLAGS = -g -Wall -fPIC -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux \
	$(shell $(WOLFSSL_CONFIG) --cflags)
WOLFSSL_SRC ?= ../../../../wolfssl/wolfssl
INTERNAL_CFLAGS = $(CFLAGS) -I$(WOLFSSL_SRC)
LDFLAGS = -shared $(shell $(WOLFSSL_CONFIG) --libs) -lm

TARGET = libwolf_jni_tls.so
SOURCES = wolf_jni_tls.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(INTERNAL_CFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
