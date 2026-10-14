# se-bench — SE timing benchmarks

Simple CLI that times four SE operations over the USB CDC link (real keychain or the
host simulator `se_host`). It reuses the existing code instead of re-implementing protocols:

| Benchmark | What is timed | Existing code called |
| --- | --- | --- |
| `handshake` | arm `ENCRYPT <unix>` + PQC mutual TLS handshake with the SE (wolfSSL on the device), closed before any request (no pad consumed) | `SeUsbLink.open`, `SeUsbTls.run(usb, ctx, "ENCRYPT", true, io)` with the owner context from `SoftwareTls.createContextFromPkcs12/Pem` (same as user-app) |
| `encrypt` | full ENCRYPT round trip: TLS session, PIN + plaintext request, encrypt reply | `ChipService.encrypt(pin, message)` (the user-app `ENCRYPT` command) |
| `padwrite` | SAE side of `PROVISION`: TLS + exporter binding, verified uplink, ML-KEM sealing of random pads, wait for `TROPIC_WIPE_FINISHED`, write downlink into TROPIC01 R-MEM, `SE_OK` | `SeUsbTls.run(..., "PROVISION", ...)`, `SeSessionBinding.HandshakeExporter` / `wrapTrustManagers`, `SeSessionUplink.readAndVerify`, `SeKemFill.buildDownlink`, `SeProvisionAck.awaitWipeFinished/writeTracking/read` (same sequence as `Node.oneProvisionSession`) |
| `initlab` | the `INIT LAB` flow without console prompts: preflight, OWNER SET, ECC KEYGEN, KEM INIT (PIN), CLIENT CSR, local CSR signing by the client CA, INSERT SIGNED CSR | `ChipInit.enroll(new OwnerAuth(usb, ctx), ChipInit.FILE_CERTS, Profile.LAB, EnrollRequest)` (what `ChipInit.run` calls after its prompts) |

The main class is `fel.cvut.userapp.SeBench`. It sits in the `fel.cvut.userapp` package only so it
can call the package-private `ChipService`, `OwnerAuth` and `ChipInit` classes. Their code is not changed.

Output: per-iteration ms on the console, a summary (n, min, max, mean, median, sample stddev),
and a CSV file `<out>/<yyyyMMdd-HHmmss>.csv` with per-iteration rows plus a summary block.
Warm-up iterations (`--warmup`, default 1) are printed but not counted.

## Build / help

```bash
cd JAVA_APPS
mvn -B -q -pl modules/se-bench -am install -DskipTests
mvn -B -q -pl modules/se-bench exec:java -Dexec.args="--help"
```

## State requirements and safety

- `handshake` and `encrypt` need an enrolled chip (INIT LAB done with the same owner identity).
  `encrypt` also needs loaded pads, and it **consumes one pad per iteration**, warm-up included.
- `padwrite` is **destructive**. The chip wipes R-MEM and stores new random pads, so any existing
  shared keys on that device become useless. It needs an SAE identity trusted by the chip: either
  `SEBENCH_SAE_P12`/`SEBENCH_SAE_P12_PASSWORD`, or `--sae-ca-p12 <root-ca.p12>`. The second option
  signs an ephemeral in-memory leaf and writes nothing to disk.
- `initlab` is **destructive and one-shot**. It enrolls owner, keys, PIN and certificate, and writes
  `client/client-cert.pem` + `client-csr.hex` into the certs dir. INIT LAB refuses an already
  provisioned chip, so each iteration needs a fresh chip: use `--reset-cmd`.
- `padwrite` and `initlab` only run with `--yes-destructive`. Without it they are skipped.
- **Never run `padwrite`/`initlab` against a real keychain unless you intend to re-enroll it.**

## Non-destructive run against the host simulator (recommended)

`sim.sh` starts a **private** TROPIC01 `model_server` (port 28997) and `se_host` on the PTY
`/tmp/ttyACM-bench`. It never touches the lab simulators (28992/28993, `/tmp/ttyACM-se1/se2`)
or any USB device. Every `sim.sh restart` is a brand-new chip, because the model and the host NV live
in RAM. Run the benchmarks against a **copy** of the certs dir so INIT LAB cannot overwrite the lab
device certificate:

```bash
cd JAVA_APPS
modules/se-bench/sim.sh start
rm -rf /tmp/se-bench-certs && cp -r certs /tmp/se-bench-certs
set -a; source env/userapp-1.env; source env/certgen.env; set +a
export USB_SERIAL_PORT=/tmp/ttyACM-bench PQC_CERTS_DIR=/tmp/se-bench-certs
export SEBENCH_PIN=12345678 SEBENCH_OWNER_PASSWORD=benchowner1 SEBENCH_SAE_CA_P12_PASSWORD="$PKCS12_PASSWORD"
# 1) INIT LAB, fresh simulated chip before every iteration
mvn -B -q -pl modules/se-bench exec:java -Dexec.args="--bench initlab --yes-destructive \
  --out modules/se-bench/bench-results --reset-cmd '$PWD/modules/se-bench/sim.sh restart'"
# 2) pad write, handshake, encrypt on the chip enrolled by the last INIT LAB iteration
mvn -B -q -pl modules/se-bench exec:java -Dexec.args="--bench padwrite,handshake,encrypt --pads 64 \
  --yes-destructive --out modules/se-bench/bench-results --sae-ca-p12 /tmp/se-bench-certs/ca/root-ca.p12"
modules/se-bench/sim.sh stop
```

`--timeout-sec` (default 120) marks a hung iteration as failed, closes the link and continues.

## Real device (non-destructive subset only)

```bash
mvn -B -q -pl modules/se-bench exec:java -Dexec.args="--bench handshake,encrypt --port /dev/ttyACM0"
```
Remember that `encrypt` still consumes pads.