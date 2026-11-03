# se-bench — SE timing benchmarks

Simple CLI that times four SE operations over the USB CDC link (real keychain or the
host simulator `se_host`). It calls the application code directly rather than re-implementing protocols:

| Benchmark | What is timed | Code called |
| --- | --- | --- |
| `handshake` | arm `ENCRYPT <unix>` + PQC mutual TLS handshake with the SE (wolfSSL on the device), closed before any request (no pad consumed) | `SeUsbLink.open`, `SeUsbTls.run(usb, ctx, "ENCRYPT", true, io)` with the owner context from `SoftwareTls.createContextFromPkcs12/Pem` (same as user-app) |
| `encrypt` | full ENCRYPT round trip: TLS session, PIN + plaintext request, encrypt reply (ENCRYPT only; the device decrypts nothing) | `ChipService.encrypt(pin, message)`, the method the user-app `ENCRYPT` command calls, with its own owner `SSLContext` built like `UserApplication.main`. While it runs, a print-only watch line every 5 s shows whether the link is open, unread TLS bytes and any device console text (debug aid for the lost-reply hang) |
| `padwrite` | SAE side of `PROVISION`: TLS + exporter binding, verified uplink, ML-KEM sealing of random pads, wait for `TROPIC_WIPE_FINISHED`, write downlink into TROPIC01 R-MEM, `SE_OK` | `SeUsbTls.run(..., "PROVISION", ...)`, `SeSessionBinding.HandshakeExporter` / `wrapTrustManagers`, `SeSessionUplink.readAndVerify`, `SeKemFill.buildDownlink`, `SeProvisionAck.awaitWipeFinished/writeTracking/read` (same sequence as `Node.oneProvisionSession`) |
| `initlab` | the `INIT LAB` flow without console prompts: preflight, OWNER SET, ECC KEYGEN, KEM INIT (PIN), CLIENT CSR, local CSR signing by the client CA, INSERT SIGNED CSR | `ChipInit.enroll(new OwnerAuth(usb, ctx), ChipInit.FILE_CERTS, Profile.LAB, EnrollRequest)` (what `ChipInit.run` calls after its prompts) |
| `ownerreplace` | reported by `initlab`: the MANAGE `OWNER REPLACE` that resets an enrolled chip before each INIT LAB iteration (not recorded when skipped on a never-enrolled chip) | `ChipService.ownerReplace(pw, pw, ownerSpki)` (the user-app `REPLACE` command) |

> **Warning: `initlab` RESETS THE CHIP.** Before every iteration (warm-up included) it runs
> `OWNER REPLACE`, which wipes the chip's contents: all pads, the ML-KEM seed, the PIN data, the
> Tropic ECC key, the device key and certificate, the SAE CA and the peers. Only the owner and the
> pairing key stay. See [State requirements](#state-requirements).

The main class is `fel.cvut.userapp.SeBench`. It sits in the `fel.cvut.userapp` package only so it
can call the package-private `ChipService`, `OwnerAuth` and `ChipInit` classes.

Handshake time is measured only by the separate `handshake` benchmark. The other stages report
their total time only; there are no per-stage `.hs` results and no `(handshake … ms)` console text.
`encrypt` calls `ChipService.encrypt` and the initlab OWNER REPLACE calls `ChipService.ownerReplace`,
the same methods the user app uses, instead of inlined `SeUsbTls.run` copies. `padwrite` still
mirrors `Node.oneProvisionSession` step by step, because that method is private to the SAE node and
needs its RMI/DB/operator setup.

The `encrypt` stage opens one serial link at its start, waits 2 s (untimed) and reuses that link
for the warm-up and every iteration, like the user app's `UsbSession` (one link opened at startup,
reused by every command). Encrypt message: by default 9216 B (9 KiB) of repeating printable ASCII
(`0-9A-Za-z`), set with `--message-size N`, or any text with `--message TEXT` (not both, not empty).
With 415 B pads one 9216 B ENCRYPT consumes 23 pads (the last one only partly, 86 B), so the
default warm-up 1 + 10 iterations need 253 of the 254 encrypt-half pads. At the start of the
encrypt stage the bench reads `TROPIC PAD LEN` and `TROPIC OTP STATUS` (the same
`ChipService.tropicPadLen` / `otpStatus` calls as the user app), prints message size, pads per
ENCRYPT, total pads needed and encrypt pads left, and stops the stage before anything is sent
when the total does not fit (run padwrite first, or lower `--message-size`, `--iterations` or
`--warmup`).

Output: per-iteration ms on the console, a summary (n, min, max, mean, median, sample stddev),
and a CSV file `<out>/<yyyyMMdd-HHmmss>.csv` with per-iteration rows plus a summary block.
Warm-up iterations (`--warmup`, default 1) are printed but not counted.

## Build / help

```bash
cd JAVA_APPS
mvn -B -q -pl modules/se-bench -am install -DskipTests
mvn -B -q -pl modules/se-bench exec:java -Dexec.args="--help"
```

## State requirements

- The firmware NV record is version 9. Any other version with magic `SENV` is `DEVICE_TAMPERED`.
  Erase the flash and set the chip up again before benchmarking.
- `handshake` and `encrypt` need an enrolled chip (INIT LAB done with the same owner identity).
  `encrypt` also needs loaded pads, and it **consumes one pad per iteration**, warm-up included.
- `padwrite` acts as the SAE and replaces the pads stored on the chip (TROPIC01 R-MEM) with random
  benchmark pads. By default it writes **all** pads, i.e. the uplink budget
  (`uplink.maxPadsForBudget`, the same maximum the SAE node uses); `--pads N` writes fewer (capped by
  the budget). `SeKemFill` splits the N pads 50/50: the first N/2 go to the decrypt half and the
  rest to the encrypt half (with `DECRYPT_HALF_ORIGIN` the encrypt half is the second one), so
  `encrypt` has about N/2 pads (one per iteration, warm-up included). `--pads 1` leaves a single
  encrypt pad. `TROPIC OTP STATUS` reports per half the bytes left and the bytes this fill wrote
  (`enc=left/written B dec=left/written B`), so after a partial fill it shows exactly where the fill
  ended; once the encrypt half's written pads are used, `encrypt` fails with OTP error 1
  (`EXHAUSTED`). No real SAE node holds the other half of those pads, so the pads that were on the
  chip before the run can no longer be used; provision the chip again from the real SAE nodes to use
  it normally after benchmarking. Device identity, owner, keys and certificates are not touched. It
  needs an SAE identity trusted by the chip: either `SEBENCH_SAE_P12`/`SEBENCH_SAE_P12_PASSWORD`, or
  the SAE root CA PKCS#12 via `--sae-ca-p12 <root-ca.p12>` or `SEBENCH_SAE_CA_P12`. The root CA
  option signs an ephemeral in-memory leaf and writes nothing to disk.
- `initlab` **resets the chip** before every iteration, warm-up included (untimed for INIT LAB, but
  timed on its own as `ownerreplace`). When `TROPIC KEM PUB` shows an enrolled chip (the same check
  INIT LAB refuses on), it sends MANAGE `OWNER REPLACE` with old = new = `SEBENCH_OWNER_PASSWORD` and
  the same owner key. That wipes all TROPIC01 user-data slots (pads, ML-KEM seed, PIN data), the
  Tropic ECC key, the device ML-DSA key and certificate, the SAE CA, peers and pad cursors; it keeps
  the owner (same password and key) and the pairing key. Nothing irreversible is done: no pairing
  slot is invalidated and no OTP / config is written. A never-enrolled chip skips the replace.
  Then the timed part runs the `INIT LAB` flow (OWNER SET, KEYGEN, KEM INIT, CLIENT CSR, local
  signing, INSERT SIGNED CSR).
  - `SEBENCH_OWNER_PASSWORD` must be the chip's **current** owner password (the one set when it was
    enrolled). A wrong one makes `OWNER REPLACE` fail (status 12) and the benchmark stops; nothing is
    wiped in that case.
  - Each iteration gives the chip a new device key and certificate and overwrites
    `client/client-cert.pem` and `client-csr.hex` in the certs dir (point `PQC_CERTS_DIR` or
    `USERAPP_DEVICE_CERT` at a copy if that matters).
  - On a real device, re-provision it from the real SAE nodes afterwards: the client hash changed,
    so the nodes must register it again (PEER ADD) and load new pads.
  - `--timeout-sec` covers OWNER REPLACE + INIT LAB together. With `--reset-cmd` the command runs
    first; on a freshly reset simulator the chip is not enrolled and the replace is skipped.
- The default `--bench` list contains all four benchmarks, initlab first; pass `--bench` explicitly
  against a real device.

## Stop on first failure (encrypt, padwrite)

`encrypt` and `padwrite` never retry. The **first** failed iteration, warm-up included, ends the stage:

- a timeout (`--timeout-sec` / `--padwrite-timeout-sec`), an OTP error reply (any status code) or an
  I/O error is printed with its meaning, e.g. `encrypt stopped at its first failure: OTP status 4
  (PIN): ...`, followed by `no further encrypt iterations were run`;
- the remaining stages are skipped (`Stopping: encrypt failed; the remaining stages are skipped`),
  and the CSV and summary are still written with the failure counted;
- OTP status codes: `1` EXHAUSTED (no encrypt pads left), `3` PARSE, `4` PIN (each wrong PIN uses
  one of the limited PIN tries; the firmware also reports some non-PIN open failures as 4),
  `5` TAMPERED, `255` FAIL (failed while consuming the pad);
- after a timeout in `encrypt` the device may already have used a pad (it advances the pad cursor
  before it sends the reply). Check `TROPIC OTP STATUS` before running again.

`initlab` still stops on a failed OWNER REPLACE. `handshake` keeps counting failures and continues
(it uses no pad and no PIN).

`SEBENCH_PIN` is checked at startup, before anything is sent to the chip, whenever `encrypt` or
`initlab` (timed or as prep) will run. The rule is the user-app PIN prompt rule (`SeManage.pinOk`:
8-16 printable ASCII). An invalid PIN exits with status 2 and the message
`SEBENCH_PIN is invalid: ...`. The PIN itself is never printed.

## Skipping ahead: `--from STAGE`

`--from STAGE` (`initlab`, `padwrite`, `handshake` or `encrypt`) starts the timed benchmarks at STAGE.
Stages always run in the fixed order initlab → padwrite → handshake → encrypt. Every stage before
STAGE runs **once** first as untimed preparation, using the same code as the benchmark itself:

- it is printed as `== prep: <stage>` / `prep <ms>` and is not in the CSV or the summary;
- `initlab` prep resets the chip like the benchmark (OWNER REPLACE when enrolled, `--reset-cmd` if set)
  and runs INIT LAB, so it has the same warnings and env requirements;
- `padwrite` prep always writes **all** pads (the uplink budget), whatever `--pads` says, so the
  following benchmarks start from a full fill (`--pads` still applies to a timed `padwrite`);
- `handshake` prep is one handshake (no pad used);
- a failed prep stage aborts the run (`prep <stage> failed: ... -- aborting`); nothing is timed.

STAGE and every later stage are then timed normally (warm-up + iterations). `--bench` is a filter on
those timed stages and does not change the prep. With `--from padwrite --bench padwrite,encrypt`,
initlab runs as prep, then padwrite and encrypt are timed and handshake is skipped. Naming a stage
before STAGE in `--bench` is an error (it can only run as prep). `--from initlab` has no prep. Without
`--from`, nothing changes (no prep, `--bench` order as given).

```bash
# Reset + enroll + full pad fill once (untimed), then time only encrypt
mvn -B -q -pl modules/se-bench exec:java -Dexec.args="--from encrypt --iterations 20 \
  --out modules/se-bench/bench-results"
# Prep initlab once, then time padwrite, handshake and encrypt
mvn -B -q -pl modules/se-bench exec:java -Dexec.args="--from padwrite --out modules/se-bench/bench-results"
```

`--from padwrite` or later still resets the chip (initlab prep); see the warnings above.

## Run against the host simulator

`sim.sh` starts a **private** TROPIC01 `model_server` (port 28997) and `se_host` on the PTY
`/tmp/ttyACM-bench`. It never touches the lab simulators (28992/28993, `/tmp/ttyACM-se1/se2`)
or any USB device. Every `sim.sh restart` is a brand-new chip, because the model and the host NV live
in RAM. Run the benchmarks against a **copy** of the certs dir so INIT LAB does not overwrite the lab
device certificate:

```bash
cd JAVA_APPS
modules/se-bench/sim.sh start
rm -rf /tmp/se-bench-certs && cp -r certs /tmp/se-bench-certs
set -a; source env/userapp-1.env; source env/certgen.env; set +a
export USB_SERIAL_PORT=/tmp/ttyACM-bench PQC_CERTS_DIR=/tmp/se-bench-certs
export SEBENCH_PIN=12345678 SEBENCH_OWNER_PASSWORD=benchowner1 SEBENCH_SAE_CA_P12_PASSWORD="$PKCS12_PASSWORD"
# 1) INIT LAB; OWNER REPLACE resets the simulated chip between iterations
#    (alternatively add --reset-cmd '$PWD/modules/se-bench/sim.sh restart' for a brand-new chip each time)
mvn -B -q -pl modules/se-bench exec:java -Dexec.args="--bench initlab --out modules/se-bench/bench-results"
# 2) pad write, handshake, encrypt on the chip enrolled by the last INIT LAB iteration
mvn -B -q -pl modules/se-bench exec:java -Dexec.args="--bench padwrite,handshake,encrypt \
  --out modules/se-bench/bench-results --sae-ca-p12 /tmp/se-bench-certs/ca/root-ca.p12"
modules/se-bench/sim.sh stop
```

`--timeout-sec` (default 120) marks a hung iteration as failed, closes the link and continues.
`padwrite` (timed or prep) uses its own `--padwrite-timeout-sec` (default 600) instead: a full fill
on the real device takes about 2 minutes (TLS handshake ~11 s plus the wipe and the pad writes), more
than the default 120 s. A prep stage that times out aborts the run like any other prep failure.

## Real device

`env/benchmark.env` (local, gitignored like the other `env/*.env`) holds the settings for the real
keychain on `/dev/ttyACM0`: owner TLS identity, SAE root CA for `padwrite`, and the INIT LAB inputs.
Node and HSM env files are not needed. Secrets that are not set (`SEBENCH_PIN`,
`SEBENCH_OWNER_PASSWORD`) are asked for on the terminal.

```bash
cd JAVA_APPS
set -a; source env/benchmark.env; set +a
mvn -B -q -pl modules/se-bench exec:java -Dexec.args="--bench padwrite,handshake,encrypt \
  --out modules/se-bench/bench-results"
```

After this the chip holds only benchmark pads (see `padwrite` above); re-provision it from the real
SAE nodes before normal use. `encrypt` consumes one pad per iteration.
`--bench initlab` resets the device before every iteration (see above) and needs its current owner
password in `SEBENCH_OWNER_PASSWORD`; afterwards the device must be re-provisioned from the real SAE
nodes.

| Variable | Used by | Meaning |
| --- | --- | --- |
| `USB_SERIAL_PORT` | all | serial port of the keychain (`--port` wins) |
| `PQC_CERTS_DIR` | all | certs dir; relative cert paths below resolve against it (default `certs`) |
| `USERAPP_OWNER_P12`, `USERAPP_OWNER_P12_PASSWORD` | all | owner TLS identity (PKCS#12) |
| `USERAPP_OWNER_CERT`, `USERAPP_OWNER_KEY` | all | PEM fallback when the PKCS#12 file is missing |
| `SEBENCH_SAE_CA_P12`, `SEBENCH_SAE_CA_P12_PASSWORD` | padwrite | SAE root CA PKCS#12 (alias `ca`); `--sae-ca-p12` wins |
| `SEBENCH_PIN` | encrypt, initlab | Tropic PIN; prompted when unset |
| `USERAPP_DEVICE_CERT`, `USERAPP_SAE_CA`, `USERAPP_CLIENT_CA_P12`, `USERAPP_CLIENT_CA_P12_PASSWORD` | initlab | device cert output path, SAE CA imported by OWNER SET, client CA used for local CSR signing |
| `SEBENCH_OWNER_PASSWORD` | initlab | the chip's CURRENT owner password: OWNER REPLACE needs it and keeps it (on a never-enrolled chip OWNER SET stores it); prompted when unset |

## Resource usage (SAE, USERAPP)

RAM and CPU of the SAE node (`fel.cvut.node.Node`) and the UserApp (`fel.cvut.userapp.UserApplication`)
are measured from outside, without code changes, in two ways: sampling `/proc` with `procmon.sh`, and
Java Flight Recorder (JFR). Both work on any JVM; neither talks to the keychain or the HSM.

How the apps run: `scripts/java.sh node env/node-N.env`, `java.sh userapp [env]` and the run-all lab
panes (`lab-node`, `lab-userapp` through `scripts/lab-run.py`) all start `mvn -pl :<module> exec:java`.
`exec:java` runs the app **inside the Maven JVM** (`org.codehaus.plexus.classworlds.launcher.Launcher`),
so:

- JVM options go in `MAVEN_OPTS`. `java.sh` sources the env files and passes the environment on
  (`lab-run.py` copies it to the child), so no script change is needed; `JAVA_OPTS` is not used.
- The measured process is that Maven JVM; its RSS, threads and heap include Maven itself (tens of MB).
  For figures without Maven, start the main class from IntelliJ (plain `java`, see below).

### A) Sampling with `procmon.sh`

```bash
cd JAVA_APPS
# terminal 1: start the app as usual
../scripts/java.sh node env/node-1.env    # or: ../scripts/java.sh userapp env/userapp-1.env
# terminal 2: sample it every second until it exits or Ctrl-C
modules/se-bench/procmon.sh --match 'Launcher.*:sae-node exec:java' --label sae \
  --out bench-results/sae-$(date +%Y%m%d-%H%M%S).csv
modules/se-bench/procmon.sh --match 'Launcher.*:user-app exec:java' --label userapp \
  --out bench-results/userapp-$(date +%Y%m%d-%H%M%S).csv
# a known PID (e.g. from IntelliJ or jps -l)
modules/se-bench/procmon.sh --pid 12345 --interval 0.5 --label userapp
```

`--match` waits until exactly one `java` process matches the `pgrep -f` pattern; with two nodes
running (run-all) use `--pid` (`jps -l` / `pgrep -af sae-node`). CSV columns: `timestamp, elapsed_s,
label, pid, cpu_total_pct` (100 % = one core, from `/proc/PID/stat` utime+stime over the measured
interval), `cpu_per_core_pct` (total / number of cores, 100 % = the whole machine), `rss_kb`,
`vmhwm_kb` (peak RSS), `threads`, and, when `jstat` is on `PATH` (disable with `--no-jstat`),
`heap_used_kb` (S0U+S1U+EU+OU of `jstat -gc`), `heap_committed_kb` and `gc_count` (YGC+FGC). On exit
it prints mean/max CPU, mean/max RSS, peak VmHWM and max heap used. The first sample includes JVM
startup if the app was started after `procmon.sh --match`.

### B) Java Flight Recorder

Script runs (`exec:java`, recording of the Maven JVM; the file is written on exit, Ctrl-C included):

```bash
cd JAVA_APPS && mkdir -p bench-results
MAVEN_OPTS="-XX:StartFlightRecording=filename=bench-results/sae-%t.jfr,settings=profile,dumponexit=true" \
  ../scripts/java.sh node env/node-1.env
MAVEN_OPTS="-XX:StartFlightRecording=filename=bench-results/userapp-%t.jfr,settings=profile,dumponexit=true" \
  ../scripts/java.sh userapp env/userapp-1.env
```

IntelliJ (plain `java`, no Maven overhead): Run → Edit Configurations → `+` Application, module
`sae-node` / `user-app`, main class `fel.cvut.node.Node` / `fel.cvut.userapp.UserApplication`,
working directory `JAVA_APPS`, env files `env/hsm.env` + `env/node-1.env` / `env/userapp-1.env`
(like the `SeBench` configuration), VM options:

```
-XX:StartFlightRecording=filename=bench-results/sae-%t.jfr,settings=profile,dumponexit=true
-XX:StartFlightRecording=filename=bench-results/userapp-%t.jfr,settings=profile,dumponexit=true
```

`%t` is the start time, so restarts do not overwrite each other. The directory must exist. Stop the
app normally (or the IntelliJ stop button, which sends SIGTERM) so `dumponexit` writes the file; a
SIGKILL loses the recording (`jcmd <pid> JFR.dump name=1 filename=...` saves it while running).

Thesis numbers from a recording (needs the JDK `jfr` tool):

```bash
modules/se-bench/procmon.sh jfr-summary bench-results/sae-2026_10_22_14_30_13.jfr
```

It prints the recording length and event counts, then mean/max process CPU (`jdk.CPULoad`
jvmUser+jvmSystem, % of **all** cores, i.e. comparable to procmon's `cpu_per_core_pct`), machine
CPU, mean/max heap used after GC and max before GC (`jdk.GCHeapSummary`), committed heap, mean/max
RSS (`jdk.ResidentSetSize`) and machine memory. For details use `jfr print --events
jdk.CPULoad,jdk.GCHeapSummary,jdk.PhysicalMemory <file>` or open the file in JDK Mission Control.

### Which memory figure to report

RSS (and VmHWM) mostly shows what the JVM reserved and touched: the heap grows to its committed
size and is rarely given back, plus metaspace, code cache, thread stacks and, for `exec:java`,
Maven. It depends on the GC and `-Xmx`, not only on the app. The **heap used after GC** (JFR
`jdk.GCHeapSummary` "After GC") is the better "memory the app needs" figure; report RSS as the
process footprint next to it. `jstat` heap used includes garbage not collected yet, so it is a
sawtooth between GCs. CPU: idle apps sit near 0 %; measure while the app is working (e.g. a node provisioning a keychain,
or user-app ENCRYPT/DECRYPT commands), and give the core count (`nproc`) with per-core figures.
