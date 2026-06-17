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
```

## Database

PostgreSQL stores client record state. Use **one database per node** (e.g. `qkd-db-sae-1` for `sae-1`).

### Setup

1. Copy `.env.example` → `.env` (or use `env/node-N.env` for multi-node).
2. Set `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` in that file.
3. Create the database:

```bash
createdb qkd-db-sae-1
```

4. Run migrations **before starting a node**:

```bash
./migrate.sh              # uses .env
./migrate.sh env/node-1.env
./migrate-all.sh          # all env/*.env (node-1, node-2, node-3, …)
```

The script loads env vars and runs `mvn flyway:migrate`.

Alternatively, with env already exported:

```bash
export DB_URL=jdbc:postgresql://localhost:5432/qkd-db-sae-1
export DB_USERNAME=postgres
export DB_PASSWORD=postgres
mvn flyway:migrate
```

### Migrations

SQL files live in `src/main/resources/db/migration/` (Flyway naming: `V1__description.sql`).

Useful commands (env must be set, same as above):

```bash
mvn flyway:info
mvn flyway:validate
```

The app reads the same `DB_*` env vars at runtime via `DatabaseConfig` — migrations are not applied automatically on startup.
