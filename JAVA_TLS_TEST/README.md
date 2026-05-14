Create a jni supporting wolfssl library
```bash
cd "$(git root)/wolfssl"

./autogen.sh

./configure \
  --enable-harden \
  --enable-wolfclu \
  --enable-ecc \
  --enable-pkcallbacks \
  --enable-keygen \
  --enable-tls13 \
  --enable-mlkem \
  --enable-dilithium \
  --enable-opensslall \
  --enable-ed25519 \
  --enable-certgen \
  --enable-base16 \
  --enable-dual-alg-certs \
  --enable-certreq \
  --enable-pwdbased \
  --enable-experimental \
  --enable-jni \
  --disable-oldtls \
  --enable-debug
make -j"$(nproc)"
sudo make install
sudo ldconfig
```
# 1. Clean the old files (this will work now that ant is installed)
make clean

# 2. Build the JNI bridge, pointing it to your isolated prefixed build
make native   WOLFSSL_INSTALL_DIR="/opt/wolfssl-jni"   WOLFSSL_LIBNAME="wolfssl"   CFLAGS="-I/opt/wolfssl-jni/include -DDEBUG_WOLFSSL -DWOLFSSL_DUAL_ALG_CERTS -Wno-unused-parameter -Wno-error"
mvn clean package -DskipTests
mvn install:install-file \
-Dfile=./target/wolfssl-jsse-1.17.0-SNAPSHOT.jar \
-DgroupId=com.wolfssl \
-DartifactId=wolfssljni \
-Dversion=1.0.0-PQC \
-Dpackaging=jar

gcc -fPIC   -I/usr/local/include   -I/usr/local/include/wolfssl   -I"$JAVA_HOME/include"   -I"$JAVA_HOME/include/linux"   -shared -o libwolf_jni_tls.so   wolf_jni_tls.c   -L/usr/local/lib -lwolfssl
