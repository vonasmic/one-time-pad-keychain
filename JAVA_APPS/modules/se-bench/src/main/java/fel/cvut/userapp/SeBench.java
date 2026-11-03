package fel.cvut.userapp;

import fel.cvut.se.EnvSecrets;
import fel.cvut.se.SeConstants;
import fel.cvut.se.SeKemFill;
import fel.cvut.se.SeManage;
import fel.cvut.se.SeProvisionAck;
import fel.cvut.se.SeSessionBinding;
import fel.cvut.se.SeSessionUplink;
import fel.cvut.se.SecureOtp;
import fel.cvut.tls.SoftwareLeaf;
import fel.cvut.tls.SoftwareTls;
import fel.cvut.tls.TlsStores;
import fel.cvut.usb.SeUsbLink;
import fel.cvut.usb.SeUsbTls;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Simple SE benchmark: times TLS handshake, INIT LAB, Tropic pad write (PROVISION) and
 * ENCRYPT round trip over USB CDC by calling the existing user-app / usb-cdc / se-wire code.
 *
 * <p>Lives in package {@code fel.cvut.userapp} only so it can reuse the package-private
 * {@link ChipService}, {@link OwnerAuth} and {@link ChipInit} without copying them.
 */
public final class SeBench {

    /** Run order: initlab enrolls a fresh chip, padwrite loads pads, then handshake/encrypt use them. */
    enum Bench { initlab, padwrite, handshake, encrypt }

    static final String HELP = """
            SE benchmark (se-bench)

            Usage: mvn -q -f JAVA_APPS/pom.xml -pl modules/se-bench exec:java -Dexec.args="[options]"

              --bench LIST       comma list of: handshake,encrypt,padwrite,initlab  (default: all)
              --from STAGE       start the timed benchmarks at STAGE (initlab|padwrite|handshake|encrypt).
                                 Stages are always run in the order initlab -> padwrite -> handshake ->
                                 encrypt; every stage BEFORE STAGE runs once first as untimed "prep" (not in
                                 the CSV/summary) so the chip state is consistent: initlab prep resets the
                                 chip (OWNER REPLACE if enrolled) and runs INIT LAB, padwrite prep writes ALL
                                 pads (ignores --pads). A failed prep stage aborts the run. With --bench,
                                 only the listed stages at or after STAGE are timed (prep is not affected);
                                 listing a stage before STAGE is an error
              --iterations N     measured iterations per benchmark (default 10)
              --warmup N         unmeasured warm-up iterations (default 1)
              --port PATH        serial port, e.g. /dev/ttyACM0 (default: USB_SERIAL_PORT or auto)
              --baud N           baud rate (default 115200)
              --out DIR          CSV output directory (default bench-results)
              --message TEXT     ENCRYPT plaintext (overrides the default 9216 B message)
              --message-size N   ENCRYPT plaintext of N bytes of repeating printable ASCII
                                 (default 9216 = 9 KiB = 23 pads of 415 B; 1 warm-up + 10 iterations
                                 use 253 of the 254 encrypt pads). Use either this or --message.
                                 Before the first ENCRYPT the bench reads TROPIC PAD LEN and
                                 TROPIC OTP STATUS, prints pads per ENCRYPT and the total needed,
                                 and does not start the stage if the encrypt half has too few pads.
              --pads N           pads written per padwrite iteration (default: all, i.e. the uplink budget
                                 uplink.maxPadsForBudget like the SAE node; N is capped by it). The pads are
                                 split 50/50: first half of N to the decrypt half, the rest to the encrypt half
              --reset-cmd CMD    shell command run (untimed) before every initlab iteration, before the
                                 OWNER REPLACE check; the serial link is closed before and reopened after
                                 it (e.g. restart the host simulator so each INIT LAB starts from a fresh
                                 chip, in which case OWNER REPLACE is skipped)
              --sae-ca-p12 PATH  padwrite: sign an ephemeral in-memory SAE leaf with this SAE root CA
                                 PKCS#12 (alias "ca", password SEBENCH_SAE_CA_P12_PASSWORD) instead of
                                 SEBENCH_SAE_P12 (default: env SEBENCH_SAE_CA_P12; the option wins)
              --timeout-sec N    per-iteration timeout (initlab: OWNER REPLACE + INIT LAB together); a hung
                                 iteration is counted as failed, the link is closed and the run continues
                                 (default 120). Not used by padwrite, see --padwrite-timeout-sec
              --padwrite-timeout-sec N  per-iteration timeout of padwrite, timed or prep (a full fill
                                 takes minutes on the real device; default 600)
              --help             this text

            Benchmarks
              handshake  arms ENCRYPT, completes the PQC TLS handshake (SeUsbTls.run), closes before
                         any request. Times arm + handshake. No pad is consumed.
              encrypt    the user-app ENCRYPT round trip: arm ENCRYPT + TLS session + PIN/plaintext request
                         + encrypt reply (ciphertext). Only ENCRYPT; nothing is decrypted on the device.
                         CONSUMES one-time pad material on every iteration (warm-up included).
                         Stops at its FIRST failed iteration (timeout, OTP error, I/O error) and skips
                         the later stages, so a wrong PIN or a lost reply never burns more PIN tries
                         or pads. padwrite stops the same way.
              padwrite   Acts as the SAE: PROVISION, read/verify uplink, ML-KEM seal random pads
                         (SeKemFill), wait for TROPIC_WIPE_FINISHED, write + SE_OK. Each iteration replaces
                         the pads stored on the chip with random benchmark pads (all pads by default).

            Handshake time is measured only by the separate handshake benchmark; the other stages report
            their total time only (no per-stage ".hs" results). encrypt calls ChipService.encrypt and the
            initlab OWNER REPLACE calls ChipService.ownerReplace, the same methods the user app uses.
            padwrite mirrors the SAE node's PROVISION session (Node.oneProvisionSession is private).
            encrypt opens ONE link at the start of the stage, waits 2 s (untimed), and reuses it for
            warm-up and all iterations, like the user app's UsbSession.
              initlab    RESETS THE CHIP before every iteration (warm-up included): when TROPIC KEM PUB shows
                         an enrolled chip, MANAGE OWNER REPLACE (old = new = SEBENCH_OWNER_PASSWORD, same
                         owner key) wipes pads, ML-KEM seed, PIN data, Tropic ECC key, device key/cert, SAE
                         CA and peers; only the owner and the pairing key stay. Its time is reported as
                         "ownerreplace" (skipped on a never-enrolled chip, then not recorded). Then the timed
                         part: ChipInit.enroll(..., Profile.LAB) = INIT LAB (owner set, keygen, KEM init,
                         local CSR signing, insert cert). A failed OWNER REPLACE stops the benchmark.

            Environment
              USERAPP_OWNER_P12 / USERAPP_OWNER_CERT / USERAPP_OWNER_KEY, USERAPP_OWNER_P12_PASSWORD
                                         owner TLS identity (same as user-app); PQC_CERTS_DIR for the certs dir
              SEBENCH_PIN                Tropic PIN (encrypt, initlab); checked at startup with the same
                                         rule as the user-app prompt (8-16 printable ASCII), never printed
              SEBENCH_SAE_P12, SEBENCH_SAE_P12_PASSWORD   SAE TLS identity trusted by the chip (padwrite)
              SEBENCH_SAE_CA_P12         SAE root CA PKCS#12 for padwrite, same as --sae-ca-p12 (relative
                                         paths resolve against the certs dir)
              SEBENCH_SAE_CA_P12_PASSWORD  password of that PKCS#12
              SEBENCH_OWNER_PASSWORD     the chip's CURRENT owner password (initlab: OWNER REPLACE keeps it;
                                         on a never-enrolled chip INIT LAB's OWNER SET stores it)
              USERAPP_DEVICE_CERT, USERAPP_SAE_CA, USERAPP_CLIENT_CA_P12, USERAPP_CLIENT_CA_P12_PASSWORD (initlab)
            """;

    public static void main(String[] args) throws Exception {
        Set<Bench> benches = new LinkedHashSet<>(List.of(Bench.values()));
        int iterations = 10;
        int warmup = 1;
        String port = env("USB_SERIAL_PORT", SeUsbLink.DEFAULT_PORT);
        int baud = SeUsbLink.DEFAULT_BAUD;
        Path outDir = Path.of("bench-results");
        String message = null;
        Integer messageSize = null;
        int pads = Integer.MAX_VALUE; // all pads; capped by the uplink budget
        String resetCmd = null;
        int timeoutSec = 120;
        int padwriteTimeoutSec = 600;
        Path saeCaP12 = null;
        Bench from = null;
        boolean benchListed = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--help", "-h" -> {
                    System.out.println(HELP);
                    return;
                }
                case "--bench" -> {
                    benchListed = true;
                    benches.clear();
                    for (String b : args[++i].split(",")) {
                        benches.add(Bench.valueOf(b.trim().toLowerCase(Locale.ROOT)));
                    }
                }
                case "--from" -> from = Bench.valueOf(args[++i].trim().toLowerCase(Locale.ROOT));
                case "--iterations" -> iterations = Integer.parseInt(args[++i]);
                case "--warmup" -> warmup = Integer.parseInt(args[++i]);
                case "--port" -> port = args[++i];
                case "--baud" -> baud = Integer.parseInt(args[++i]);
                case "--out" -> outDir = Path.of(args[++i]);
                case "--message" -> message = args[++i];
                case "--message-size" -> messageSize = Integer.parseInt(args[++i]);
                case "--pads" -> pads = Integer.parseInt(args[++i]);
                case "--reset-cmd" -> resetCmd = args[++i];
                case "--timeout-sec" -> timeoutSec = Integer.parseInt(args[++i]);
                case "--padwrite-timeout-sec" -> padwriteTimeoutSec = Integer.parseInt(args[++i]);
                case "--sae-ca-p12" -> saeCaP12 = Path.of(args[++i]);
                default -> throw new IllegalArgumentException("Unknown option " + args[i] + " (see --help)");
            }
        }
        if (iterations < 1 || warmup < 0 || pads < 1 || timeoutSec < 1 || padwriteTimeoutSec < 1) {
            throw new IllegalArgumentException(
                    "iterations >= 1, warmup >= 0, pads >= 1, timeouts >= 1");
        }
        if (saeCaP12 == null && !env("SEBENCH_SAE_CA_P12", "").isEmpty()) {
            saeCaP12 = certPath(SoftwareTls.certsDir(), "SEBENCH_SAE_CA_P12", "");
        }
        List<Bench> prep = new ArrayList<>();
        if (from != null) {
            for (Bench b : Bench.values()) {
                if (b.ordinal() < from.ordinal()) {
                    if (benchListed && benches.contains(b)) {
                        throw new IllegalArgumentException("--bench " + b + " is before --from " + from
                                + "; it only runs once as untimed prep");
                    }
                    prep.add(b);
                }
            }
            Set<Bench> timed = new LinkedHashSet<>();
            for (Bench b : Bench.values()) {
                if (b.ordinal() >= from.ordinal() && (!benchListed || benches.contains(b))) {
                    timed.add(b);
                }
            }
            benches = timed;
        }
        if (benches.contains(Bench.padwrite) || prep.contains(Bench.padwrite)) {
            System.err.println("padwrite replaces the pads stored on the chip with random benchmark pads.");
        }
        if (benches.isEmpty()) {
            System.err.println("Nothing to run.");
            return;
        }

        if (message != null && messageSize != null) {
            System.err.println("Use either --message or --message-size, not both.");
            System.exit(2);
            return;
        }
        if (message == null) {
            int size = messageSize != null ? messageSize : DEFAULT_MESSAGE_SIZE;
            if (size <= 0) {
                System.err.println("--message-size must be at least 1 byte.");
                System.exit(2);
                return;
            }
            message = benchMessage(size);
        } else if (message.isEmpty()) {
            System.err.println("--message must not be empty (same rule as the user app).");
            System.exit(2);
            return;
        }

        String pin = null;
        if (benches.contains(Bench.encrypt) || benches.contains(Bench.initlab) || prep.contains(Bench.initlab)) {
            pin = EnvSecrets.envOrScan("SEBENCH_PIN");
            if (!pinValid(pin)) {
                System.err.println("SEBENCH_PIN is invalid: the Tropic PIN must be " + SeConstants.PIN_SIZE_MIN
                        + "-" + SeConstants.PIN_SIZE_MAX + " printable ASCII characters (the user-app PIN"
                        + " prompt rule). Nothing was sent to the chip.");
                System.exit(2);
                return;
            }
        }

        SeBench bench = new SeBench(message, pin, pads, port, baud, resetCmd, saeCaP12);
        bench.timeoutSec = timeoutSec;
        bench.padwriteTimeoutSec = padwriteTimeoutSec;
        List<Result> results = new ArrayList<>();
        try {
            for (Bench b : prep) {
                bench.closeLink();
                bench.run(b, 1, 0, true); // untimed preparation; throws on failure
                bench.extras.clear();
            }
            for (Bench b : benches) {
                bench.closeLink(); // fresh CDC session per benchmark
                results.add(bench.run(b, iterations, warmup, false));
                results.addAll(bench.extras); // ownerreplace results of this benchmark
                bench.extras.clear();
                if (bench.stageAborted) {
                    System.out.println("Stopping: " + b + " failed; the remaining stages are skipped"
                            + " (chip state unknown).");
                    break;
                }
            }
        } finally {
            bench.closeLink();
        }
        Path csv = writeCsv(outDir, results);
        System.out.println();
        System.out.printf(Locale.ROOT, "%-12s %4s %10s %10s %10s %10s %10s%n",
                "benchmark", "n", "min ms", "max ms", "mean ms", "median ms", "stddev ms");
        for (Result r : results) {
            r.printSummary();
        }
        System.out.println("CSV: " + csv.toAbsolutePath());
    }

    // ------------------------------------------------------------------ setup

    private final String message;
    /** Default ENCRYPT plaintext size: 9 KiB (23 pads of 415 B; 11 runs = 253 of the 254 encrypt pads). */
    static final int DEFAULT_MESSAGE_SIZE = 9 * 1024;

    /** Deterministic printable-ASCII plaintext of exactly {@code size} bytes (UTF-8 = ASCII). */
    static String benchMessage(int size) {
        String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        StringBuilder sb = new StringBuilder(size);
        for (int k = 0; k < size; k++) {
            sb.append(alphabet.charAt(k % alphabet.length()));
        }
        return sb.toString();
    }

    /**
     * Reads TROPIC PAD LEN and TROPIC OTP STATUS (ChipService.tropicPadLen / otpStatus, as the user app)
     * and checks that warm-up + iterations fit in the encrypt half. Returns null when they fit,
     * otherwise why the stage must not start. Prints the budget either way.
     */
    private String checkEncryptBudget(int runs) throws Exception {
        ChipService chip = new ChipService(usb(), ownerCtx());
        int msgBytes = message.getBytes(StandardCharsets.UTF_8).length;
        String padLenText = chip.tropicPadLen();
        java.util.regex.Matcher pm = java.util.regex.Pattern.compile("(\\d+)").matcher(padLenText == null ? "" : padLenText);
        if (!pm.find() || Integer.parseInt(pm.group(1)) <= 0) {
            return "TROPIC PAD LEN gave no pad size (" + oneLine(padLenText) + ")";
        }
        int padLen = Integer.parseInt(pm.group(1));
        String status = chip.otpStatus();
        java.util.regex.Matcher sm = java.util.regex.Pattern.compile("enc=(\\d+)/(\\d+)").matcher(status == null ? "" : status);
        if (!sm.find()) {
            return "TROPIC OTP STATUS has no enc=left/cap field (" + oneLine(status) + ")";
        }
        long encLeftBytes = Long.parseLong(sm.group(1));
        long encCapBytes = Long.parseLong(sm.group(2));
        int padsPerEncrypt = (msgBytes + padLen - 1) / padLen;
        long needed = (long) padsPerEncrypt * runs;
        long encLeftPads = encLeftBytes / padLen;
        System.out.println("   encrypt: message " + msgBytes + " B, pad " + padLen + " B -> " + padsPerEncrypt
                + " pads per ENCRYPT x " + runs + " (warm-up + iterations) = " + needed + " pads; encrypt half has "
                + encLeftPads + " of " + (encCapBytes / padLen) + " pads left");
        if (needed > encLeftPads) {
            return "needs " + needed + " encrypt pads but only " + encLeftPads
                    + " are left (run padwrite, or lower --message-size / --iterations / --warmup)";
        }
        return null;
    }

    private static String oneLine(String s) {
        return s == null ? "no reply" : s.strip().replace("\r", " ").replace("\n", " | ");
    }

    /** Untimed pause after opening the encrypt-stage link (the app opens its link long before ENCRYPT). */
    static final long ENCRYPT_SETTLE_MS = 2_000;
    /** Validated SEBENCH_PIN (null when no stage needs it). Never printed. */
    private final String pin;
    private final int pads;
    /** Set when a stop-on-first-failure stage (encrypt, padwrite) failed; main skips later stages. */
    private boolean stageAborted;
    private SSLContext ownerCtx;
    private SSLContext saeCtx;
    private final SecureRandom random = new SecureRandom();

    private final String port;
    private final int baud;
    private final String resetCmd;
    private final Path saeCaP12;
    private SeUsbLink link;
    private int timeoutSec = 120;
    private int padwriteTimeoutSec = 600;
    /** OWNER REPLACE times taken before INIT LAB iterations (reported as their own benchmark). */
    private final Result ownerReplace = new Result("ownerreplace");
    /** OWNER REPLACE time of the current initlab iteration, or -1 when it was skipped. */
    private volatile long lastReplaceNs = -1;
    /** Extra results produced by the last run() (ownerreplace). */
    private final List<Result> extras = new ArrayList<>();

    /** OWNER REPLACE was refused; the initlab benchmark cannot continue. */
    static final class OwnerReplaceException extends IOException {
        OwnerReplaceException(String message) {
            super(message);
        }
    }

    private SeBench(String message, String pin, int pads, String port, int baud, String resetCmd, Path saeCaP12) {
        this.message = message;
        this.pin = pin;
        this.pads = pads;
        this.port = port;
        this.baud = baud;
        this.resetCmd = resetCmd;
        this.saeCaP12 = saeCaP12;
    }

    /** Current link; reopened lazily (after a reset or when the device went away). */
    SeUsbLink usb() throws Exception {
        if (link != null && !link.isOpen()) {
            closeLink();
        }
        if (link == null) {
            link = SeUsbLink.open(port, baud);
            System.out.println("   SE link open on " + link.serialPortName());
        }
        return link;
    }

    void closeLink() {
        if (link != null) {
            link.close();
            link = null;
        }
    }

    private void reset() throws Exception {
        closeLink();
        Process p = new ProcessBuilder("bash", "-c", resetCmd).inheritIO().start();
        if (p.waitFor() != 0) {
            throw new IOException("reset command failed: " + resetCmd);
        }
    }

    @FunctionalInterface
    interface Op {
        /** Returns measured nanoseconds (or -1 to time the whole call). */
        long run() throws Exception;
    }

    /**
     * Runs @p b for warm-up + iterations. With @p prep it is one untimed preparation run: nothing is
     * recorded and a failure aborts the whole benchmark (the following stages need its state).
     */
    private Result run(Bench b, int iterations, int warmup, boolean prep) throws Exception {
        Op op = switch (b) {
            case handshake -> handshakeOp();
            case encrypt -> encryptOp();
            case padwrite -> padWriteOp(prep ? Integer.MAX_VALUE : pads); // prep: full fill
            case initlab -> initLabOp();
        };
        Result result = new Result(b.name());
        System.out.println(prep
                ? "== prep: " + b + " (once, untimed, not recorded)"
                : "== " + b + " (warm-up " + warmup + ", iterations " + iterations + ")");
        if (b == Bench.encrypt) {
            // Like UserApplication's UsbSession: one link opened up front (UserApplication.java:68),
            // left to settle, then reused by every ENCRYPT; untimed.
            usb();
            System.out.println("   encrypt: link open, settling " + ENCRYPT_SETTLE_MS + " ms before the first ENCRYPT");
            Thread.sleep(ENCRYPT_SETTLE_MS);
            String budgetProblem = checkEncryptBudget(warmup + iterations);
            if (budgetProblem != null) {
                System.out.println("   encrypt NOT started, nothing was sent: " + budgetProblem);
                result.failed++;
                stageAborted = true;
                closeLink();
                return result;
            }
        }
        for (int i = -warmup; i < iterations; i++) {
            if (b == Bench.initlab && resetCmd != null) {
                reset();
            }
            lastReplaceNs = -1;
            long t0 = System.nanoTime();
            long inner;
            int limitSec = b == Bench.padwrite ? padwriteTimeoutSec : timeoutSec;
            java.util.concurrent.ExecutorService ex = java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "se-bench-op");
                t.setDaemon(true);
                return t;
            });
            try {
                inner = ex.submit(op::run).get(limitSec, java.util.concurrent.TimeUnit.SECONDS);
            } catch (Exception e) {
                Throwable cause = e instanceof java.util.concurrent.ExecutionException && e.getCause() != null
                        ? e.getCause() : e;
                boolean timedOut = e instanceof java.util.concurrent.TimeoutException;
                String why = timedOut ? "timed out after " + limitSec + " s" : cause.getMessage();
                closeLink(); // unblocks a hung read; next iteration reopens
                ex.shutdownNow();
                if (prep) {
                    throw new IOException("prep " + b + " failed: " + why
                            + " -- aborting, the later stages would not start from a consistent state", cause);
                }
                System.out.println("   " + b + (i < 0 ? " warm-up" : " iteration " + (i + 1)) + " failed: " + why);
                result.failed++;
                if (cause instanceof OwnerReplaceException) {
                    System.out.println("   initlab stopped: OWNER REPLACE could not reset the chip");
                    break;
                }
                if (b == Bench.encrypt || b == Bench.padwrite) {
                    // Never retry an OTP stage: each try can burn a PIN attempt or a pad.
                    System.out.println("   " + b + " stopped at its first failure: "
                            + describeFailure(b, cause, timedOut, limitSec));
                    System.out.println("   no further " + b + " iterations were run");
                    stageAborted = true;
                    break;
                }
                continue;
            }
            ex.shutdown();
            double ms = (inner >= 0 ? inner : System.nanoTime() - t0) / 1e6;
            boolean record = !prep && i >= 0;
            String label = prep ? "prep" : i >= 0 ? "#" + (i + 1) : "warm-up";
            if (b == Bench.initlab && lastReplaceNs >= 0) {
                double replaceMs = lastReplaceNs / 1e6;
                if (record) {
                    ownerReplace.samples.add(replaceMs);
                }
                System.out.printf(Locale.ROOT, "   %s owner replace %.2f ms%n", label, replaceMs);
            }
            if (record) {
                result.samples.add(ms);
            }
            System.out.printf(Locale.ROOT, "   %s %.2f ms%n", label, ms);
        }
        for (Result extra : b == Bench.initlab ? List.of(ownerReplace) : List.<Result>of()) {
            if (!extra.samples.isEmpty()) {
                extras.add(extra);
            }
        }
        return result;
    }

    private SSLContext ownerCtx() throws Exception {
        if (ownerCtx == null) {
            ownerCtx = newOwnerCtx();
        }
        return ownerCtx;
    }

    /** Owner SSLContext built exactly like UserApplication.main (p12 if present, else PEM). */
    private static SSLContext newOwnerCtx() throws Exception {
        Path certs = SoftwareTls.certsDir();
        Path p12 = certPath(certs, "USERAPP_OWNER_P12", "user/user.p12");
        if (Files.isRegularFile(p12)) {
            char[] pw = EnvSecrets.envOrScan("USERAPP_OWNER_P12_PASSWORD").toCharArray();
            try {
                return SoftwareTls.createContextFromPkcs12(p12, pw, SoftwareTls.clientCaPem());
            } finally {
                Arrays.fill(pw, '\0');
            }
        }
        return SoftwareTls.createContextFromPem(
                certPath(certs, "USERAPP_OWNER_CERT", "user/user-cert.pem"),
                certPath(certs, "USERAPP_OWNER_KEY", "user/user-key.pem"),
                SoftwareTls.clientCaPem());
    }

    // ------------------------------------------------------------- benchmarks

    /** Arm ENCRYPT + PQC handshake via SeUsbTls.run, close before sending a request. */
    private Op handshakeOp() throws Exception {
        SSLContext ctx = ownerCtx();
        return () -> {
            SeUsbLink usb = usb();
            long t0 = System.nanoTime();
            return SeUsbTls.run(usb, ctx, "ENCRYPT", true, ssl -> System.nanoTime() - t0);
        };
    }

    /**
     * user-app ENCRYPT: ChipService.encrypt(pin, message), the method UserApplication.runEncryptFlow
     * calls. Own SSLContext built like UserApplication.main (not shared with the earlier stages).
     */
    private Op encryptOp() throws Exception {
        if (pin == null) {
            throw new IllegalStateException("SEBENCH_PIN was not loaded");
        }
        if (message.isEmpty()) {
            throw new IllegalArgumentException("--message must not be empty (same rule as the user app)");
        }
        SSLContext ctx = newOwnerCtx();
        return () -> {
            SeUsbLink usb = usb();
            ChipService chip = new ChipService(usb, ctx);
            Thread watch = startReplyWatch(usb, message.getBytes(StandardCharsets.UTF_8).length);
            try {
                byte[] reply = chip.encrypt(pin, message);
                if (reply == null || reply.length == 0) {
                    throw new IOException("empty encrypt reply");
                }
            } finally {
                watch.interrupt();
            }
            return -1;
        };
    }

    /**
     * Debug aid for the encrypt hang: while ChipService.encrypt runs, print every 5 s whether
     * the link is still open, how many SECURE bytes sit unread in the link buffer, and any
     * console (CMD frame) text the device sent. Print only; never prints the request or PIN.
     */
    private static Thread startReplyWatch(SeUsbLink usb, int messageLen) {
        long start = System.nanoTime();
        System.out.println("   encrypt: ChipService.encrypt started (" + messageLen + " B message)");
        Thread t = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(5_000);
                } catch (InterruptedException e) {
                    return;
                }
                long s = (System.nanoTime() - start) / 1_000_000_000L;
                String line;
                try {
                    boolean open = usb.isOpen();
                    int buffered = usb.getInputStream().available();
                    String console = open ? usb.readConsole(100, 300).strip() : "";
                    line = "   [watch " + s + " s] link open=" + open + ", unread TLS bytes=" + buffered
                            + (console.isEmpty() ? ", no console text" : ", console: " + console.replace("\n", " | "));
                } catch (Exception e) {
                    line = "   [watch " + s + " s] probe failed: " + e;
                }
                System.out.println(line);
            }
        }, "se-bench-watch");
        t.setDaemon(true);
        t.start();
        return t;
    }

    /** SAE side of PROVISION, as in Node.oneProvisionSession, with random pad material. */
    private Op padWriteOp(int pads) throws Exception {
        SSLContext ctx = saeCtx();
        SeKemFill fill = new SeKemFill(random);
        return () -> {
            SeUsbLink usb = usb();
            SeSessionBinding.HandshakeExporter exporter = new SeSessionBinding.HandshakeExporter();
            javax.net.ssl.SSLSocket[] attached = new javax.net.ssl.SSLSocket[1];
            try {
                SeUsbTls.run(usb, ctx, "PROVISION", true,
                        ssl -> {
                            ssl.setSoTimeout(100_000);
                            attached[0] = ssl;
                            exporter.attach(ssl);
                        },
                        ssl -> {
                            SeSessionUplink uplink = SeSessionUplink.readAndVerify(ssl, exporter.require());
                            int padPlain = uplink.plainMax();
                            int n = Math.min(pads, uplink.maxPadsForBudget(padPlain));
                            System.out.println("   padwrite: " + n + " pads x " + padPlain + " B ("
                                    + n / 2 + " decrypt half, " + (n - n / 2) + " encrypt half)");
                            byte[] material = new byte[n * padPlain];
                            random.nextBytes(material);
                            byte[] payload = fill.buildDownlink(uplink,
                                    List.of(Base64.getEncoder().encodeToString(material)),
                                    SeConstants.DECRYPT_HALF_ORIGIN, padPlain);
                            ssl.setSoTimeout(300_000);
                            SeProvisionAck.awaitWipeFinished(ssl.getInputStream());
                            SeProvisionAck.writeTracking(ssl.getOutputStream(), ssl.getInputStream(), payload, null);
                            SeProvisionAck.read(ssl.getInputStream());
                            return null;
                        });
            } finally {
                exporter.detach(attached[0]);
            }
            return -1;
        };
    }

    /**
     * INIT LAB without the console prompts: ChipInit.enroll(..., Profile.LAB). An enrolled chip
     * (ML-KEM public key present, the same check INIT LAB refuses on) is first reset with
     * OWNER REPLACE, timed separately; only the enroll call is the initlab sample.
     */
    private Op initLabOp() throws Exception {
        SSLContext ctx = ownerCtx();
        Path certs = SoftwareTls.certsDir();
        Path deviceCert = certPath(certs, "USERAPP_DEVICE_CERT", "client/client-cert.pem");
        Path saeCa = certPath(certs, "USERAPP_SAE_CA", "ca/root-ca.pem");
        Path clientCaP12 = certPath(certs, "USERAPP_CLIENT_CA_P12", "ca/client_ca.p12");
        String clientCaPw = EnvSecrets.envOrScan("USERAPP_CLIENT_CA_P12_PASSWORD");
        String ownerPw = EnvSecrets.envOrScan("SEBENCH_OWNER_PASSWORD");
        if (pin == null) {
            throw new IllegalStateException("SEBENCH_PIN was not loaded");
        }
        byte[] ownerSpki = PeerCertHash.rawSpkiBits(ownerCert());
        byte[] saeCaDer = TlsStores.readPemCerts(saeCa).get(0).getEncoded();
        Path parent = deviceCert.getParent();
        String deviceCn = parent != null && "client2".equals(parent.getFileName().toString())
                ? SoftwareLeaf.DEVICE_CLIENT_CN_2 : SoftwareLeaf.DEVICE_CLIENT_CN;
        byte[] ownerPwBytes = ownerPw.getBytes(StandardCharsets.US_ASCII);
        return () -> {
            if (new OwnerAuth(usb(), ctx).tropicKemPub().isPresent()) {
                // Same method the user app's OWNER REPLACE uses (UserApplication -> ChipService.ownerReplace).
                ChipService replacer = new ChipService(usb(), ctx);
                long r0 = System.nanoTime();
                SeManage.Reply replaced = replacer.ownerReplace(ownerPwBytes, ownerPwBytes, ownerSpki);
                long replaceNs = System.nanoTime() - r0;
                if (!replaced.ok()) {
                    throw new OwnerReplaceException("OWNER REPLACE failed (status " + replaced.status() + ": "
                            + replaced.describe() + ")" + (replaced.status() == SeManage.PW_FAIL
                            ? "; SEBENCH_OWNER_PASSWORD is not the chip's current owner password" : ""));
                }
                lastReplaceNs = replaceNs;
                closeLink(); // fresh CDC session for INIT LAB
            }
            OwnerAuth chip = new OwnerAuth(usb(), ctx);
            long t0 = System.nanoTime();
            ChipInit.EnrollResult r = ChipInit.enroll(chip, ChipInit.FILE_CERTS,
                    ChipInit.Profile.LAB, new ChipInit.EnrollRequest(
                            ownerPwBytes, pin, Optional.empty(),
                            deviceCert, clientCaP12, clientCaPw, deviceCn, ownerSpki, saeCaDer));
            long enrollNs = System.nanoTime() - t0;
            if (!r.ok()) {
                throw new IOException("INIT LAB stopped at " + r.stoppedAt() + ": " + r.message());
            }
            return enrollNs;
        };
    }

    private X509Certificate ownerCert() throws Exception {
        Path certs = SoftwareTls.certsDir();
        Path p12 = certPath(certs, "USERAPP_OWNER_P12", "user/user.p12");
        if (Files.isRegularFile(p12)) {
            char[] pw = EnvSecrets.envOrScan("USERAPP_OWNER_P12_PASSWORD").toCharArray();
            try {
                return SoftwareTls.softwareLeafFromPkcs12(p12, pw);
            } finally {
                Arrays.fill(pw, '\0');
            }
        }
        return SoftwareTls.softwareLeafFromPem(certPath(certs, "USERAPP_OWNER_CERT", "user/user-cert.pem"));
    }

    /** SAE command-server context: SAE identity, trusts the client CA, captures the TLS exporter. */
    private SSLContext saeCtx() throws Exception {
        if (saeCtx == null) {
            SoftwareTls.installSoftware();
            if (saeCaP12 != null) {
                saeCtx = ephemeralSaeCtx();
                return saeCtx;
            }
            String p12Spec = System.getenv("SEBENCH_SAE_P12");
            if (p12Spec == null || p12Spec.isBlank()) {
                throw new IllegalStateException("padwrite needs SEBENCH_SAE_P12 (SAE node PKCS#12)");
            }
            Path p12 = Path.of(p12Spec);
            char[] pw = EnvSecrets.envOrScan("SEBENCH_SAE_P12_PASSWORD").toCharArray();
            try {
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
                kmf.init(TlsStores.loadPkcs12(p12, pw), pw);
                Path clientCa = SoftwareTls.clientCaPem();
                TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
                tmf.init(TlsStores.trustStoreFromCert(TlsStores.readPemCerts(clientCa).get(0), clientCa));
                SSLContext ctx = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
                ctx.init(kmf.getKeyManagers(), SeSessionBinding.wrapTrustManagers(tmf.getTrustManagers()),
                        new SecureRandom());
                saeCtx = ctx;
            } finally {
                Arrays.fill(pw, '\0');
            }
        }
        return saeCtx;
    }

    /** In-memory ML-DSA-44 SAE leaf signed by the SAE root CA; nothing is written to disk. */
    private SSLContext ephemeralSaeCtx() throws Exception {
        char[] caPw = EnvSecrets.envOrScan("SEBENCH_SAE_CA_P12_PASSWORD").toCharArray();
        try {
            KeyStore caStore = TlsStores.loadPkcs12(saeCaP12, caPw);
            java.security.PrivateKey caKey = (java.security.PrivateKey) caStore.getKey("ca", caPw);
            X509Certificate caCert = (X509Certificate) caStore.getCertificate("ca");
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("ML-DSA", "BC");
            kpg.initialize(org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44);
            java.security.KeyPair kp = kpg.generateKeyPair();
            long now = System.currentTimeMillis();
            var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                    caCert, java.math.BigInteger.valueOf(now), new java.util.Date(now - 60_000),
                    new java.util.Date(now + 86_400_000L), new org.bouncycastle.asn1.x500.X500Name("CN=se-bench-sae"),
                    kp.getPublic());
            X509Certificate leaf = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider("BC")
                    .getCertificate(builder.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                            caKey.getAlgorithm()).setProvider("BC").build(caKey)));
            char[] pw = "se-bench".toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(null, null);
            ks.setKeyEntry("sae", kp.getPrivate(), pw, new java.security.cert.Certificate[]{leaf, caCert});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            kmf.init(ks, pw);
            Path clientCa = SoftwareTls.clientCaPem();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            tmf.init(TlsStores.trustStoreFromCert(TlsStores.readPemCerts(clientCa).get(0), clientCa));
            SSLContext ctx = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
            ctx.init(kmf.getKeyManagers(), SeSessionBinding.wrapTrustManagers(tmf.getTrustManagers()),
                    new SecureRandom());
            return ctx;
        } finally {
            Arrays.fill(caPw, '\0');
        }
    }

    /** Same rule as the user-app PIN prompt (SeManage.pinOk), plus: every char printable ASCII. */
    static boolean pinValid(String pin) {
        if (pin == null || !SeManage.pinOk(pin)) {
            return false;
        }
        for (int k = 0; k < pin.length(); k++) {
            char c = pin.charAt(k);
            if (c < 0x20 || c > 0x7E) {
                return false;
            }
        }
        return true;
    }

    /** Human-readable reason for a stop-on-first-failure stage; never contains the PIN. */
    static String describeFailure(Bench b, Throwable cause, boolean timedOut, int limitSec) {
        if (timedOut) {
            return "no reply within " + limitSec + " s (link closed)."
                    + (b == Bench.encrypt
                    ? " The device may already have consumed a pad: it advances the pad cursor before it sends"
                    + " the reply. Check TROPIC OTP STATUS before running again."
                    : "");
        }
        for (Throwable t = cause; t != null; t = t.getCause()) {
            if (t instanceof SecureOtp.OtpException otp) {
                String hint = switch (otp.code()) {
                    case SecureOtp.ERR_PIN -> "the chip refused the PIN open; each wrong PIN uses one of the"
                            + " limited PIN tries, so check SEBENCH_PIN (the firmware also reports some"
                            + " non-PIN open failures as 4)";
                    case SecureOtp.ERR_EXHAUSTED -> "no encrypt pads left in this fill; run padwrite first";
                    case SecureOtp.ERR_PARSE -> "the chip could not parse the OTP request";
                    case SecureOtp.ERR_TAMPERED -> "the chip reports DEVICE_TAMPERED; inspect it before"
                            + " running anything else";
                    case SecureOtp.ERR_FAIL -> "the chip failed while consuming the pad (a pad may be used up)";
                    default -> "unknown OTP status";
                };
                return "OTP status " + otp.code() + " (" + SecureOtp.OtpException.nameFor(otp.code()) + "): "
                        + hint;
            }
        }
        return "I/O error: " + cause.getClass().getSimpleName() + ": " + cause.getMessage();
    }

    // ---------------------------------------------------------------- output

    static final class Result {
        final String name;
        final List<Double> samples = new ArrayList<>();
        int failed;

        Result(String name) {
            this.name = name;
        }

        double min() { return samples.stream().mapToDouble(d -> d).min().orElse(Double.NaN); }
        double max() { return samples.stream().mapToDouble(d -> d).max().orElse(Double.NaN); }
        double mean() { return samples.stream().mapToDouble(d -> d).average().orElse(Double.NaN); }

        double median() {
            if (samples.isEmpty()) {
                return Double.NaN;
            }
            double[] s = samples.stream().mapToDouble(d -> d).sorted().toArray();
            return s.length % 2 == 1 ? s[s.length / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
        }

        /** Sample standard deviation (n-1). */
        double stddev() {
            if (samples.size() < 2) {
                return 0;
            }
            double m = mean();
            double sum = samples.stream().mapToDouble(d -> (d - m) * (d - m)).sum();
            return Math.sqrt(sum / (samples.size() - 1));
        }

        void printSummary() {
            System.out.printf(Locale.ROOT, "%-12s %4d %10.2f %10.2f %10.2f %10.2f %10.2f%s%n",
                    name, samples.size(), min(), max(), mean(), median(), stddev(),
                    failed > 0 ? "  (" + failed + " failed)" : "");
        }
    }

    static Path writeCsv(Path dir, List<Result> results) throws IOException {
        Files.createDirectories(dir);
        Path file = dir.resolve(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + ".csv");
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(file))) {
            w.println("benchmark,iteration,ms");
            for (Result r : results) {
                for (int i = 0; i < r.samples.size(); i++) {
                    w.printf(Locale.ROOT, "%s,%d,%.3f%n", r.name, i + 1, r.samples.get(i));
                }
            }
            w.println();
            w.println("benchmark,n,failed,min_ms,max_ms,mean_ms,median_ms,stddev_ms");
            for (Result r : results) {
                w.printf(Locale.ROOT, "%s,%d,%d,%.3f,%.3f,%.3f,%.3f,%.3f%n", r.name, r.samples.size(), r.failed,
                        r.min(), r.max(), r.mean(), r.median(), r.stddev());
            }
        }
        return file;
    }

    private static Path certPath(Path certsDir, String env, String defaultRel) {
        Path path = Path.of(env(env, defaultRel));
        return path.isAbsolute() ? path.normalize() : certsDir.resolve(path).normalize();
    }

    private static String env(String name, String def) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? def : v.trim();
    }
}