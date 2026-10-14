package fel.cvut.userapp;

import fel.cvut.se.EnvSecrets;
import fel.cvut.se.SeConstants;
import fel.cvut.se.SeKemFill;
import fel.cvut.se.SeProvisionAck;
import fel.cvut.se.SeSessionBinding;
import fel.cvut.se.SeSessionUplink;
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
              --iterations N     measured iterations per benchmark (default 10)
              --warmup N         unmeasured warm-up iterations (default 1)
              --port PATH        serial port, e.g. /dev/ttyACM0 (default: USB_SERIAL_PORT or auto)
              --baud N           baud rate (default 115200)
              --out DIR          CSV output directory (default bench-results)
              --message TEXT     ENCRYPT plaintext (default "bench")
              --pads N           pads written per padwrite iteration (default 1, capped by the uplink budget)
              --yes-destructive  required to run padwrite / initlab
              --reset-cmd CMD    shell command run (untimed) before every initlab iteration; the serial
                                 link is closed before and reopened after it (e.g. restart the host
                                 simulator so each INIT LAB starts from a fresh chip)
              --sae-ca-p12 PATH  padwrite: sign an ephemeral in-memory SAE leaf with this SAE root CA
                                 PKCS#12 (alias "ca", password SEBENCH_SAE_CA_P12_PASSWORD) instead of
                                 SEBENCH_SAE_P12
              --timeout-sec N    per-iteration timeout; a hung iteration is counted as failed, the link
                                 is closed and the run continues (default 120)
              --help             this text

            Benchmarks
              handshake  arms ENCRYPT, completes the PQC TLS handshake (SeUsbTls.run), closes before
                         any request. Times arm + handshake. No pad is consumed.
              encrypt    ChipService.encrypt(PIN, message): ENCRYPT TLS session + request + reply.
                         CONSUMES one-time pad material on every iteration (warm-up included).
              padwrite   DESTRUCTIVE. Acts as the SAE: PROVISION, read/verify uplink, ML-KEM seal random
                         pads (SeKemFill), wait for TROPIC_WIPE_FINISHED, write + SE_OK. The chip wipes and
                         replaces its pads with random material each iteration (existing shares unusable).
              initlab    DESTRUCTIVE / one-shot. ChipInit.enroll(..., Profile.LAB) = the INIT LAB flow
                         (owner set, keygen, KEM init, local CSR signing, insert cert). INIT LAB refuses a
                         chip whose ML-KEM key is already provisioned, so each iteration needs a freshly
                         wiped chip; the benchmark stops at the first refusal.

            Environment
              USERAPP_OWNER_P12 / USERAPP_OWNER_CERT / USERAPP_OWNER_KEY, USERAPP_OWNER_P12_PASSWORD
                                         owner TLS identity (same as user-app); PQC_CERTS_DIR for the certs dir
              SEBENCH_PIN                Tropic PIN (encrypt, initlab)
              SEBENCH_SAE_P12, SEBENCH_SAE_P12_PASSWORD   SAE TLS identity trusted by the chip (padwrite)
              SEBENCH_OWNER_PASSWORD     owner reset password (initlab)
              USERAPP_DEVICE_CERT, USERAPP_SAE_CA, USERAPP_CLIENT_CA_P12, USERAPP_CLIENT_CA_P12_PASSWORD (initlab)
            """;

    public static void main(String[] args) throws Exception {
        Set<Bench> benches = new LinkedHashSet<>(List.of(Bench.values()));
        int iterations = 10;
        int warmup = 1;
        String port = env("USB_SERIAL_PORT", SeUsbLink.DEFAULT_PORT);
        int baud = SeUsbLink.DEFAULT_BAUD;
        Path outDir = Path.of("bench-results");
        String message = "bench";
        int pads = 1;
        boolean destructiveOk = false;
        String resetCmd = null;
        int timeoutSec = 120;
        Path saeCaP12 = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--help", "-h" -> {
                    System.out.println(HELP);
                    return;
                }
                case "--bench" -> {
                    benches.clear();
                    for (String b : args[++i].split(",")) {
                        benches.add(Bench.valueOf(b.trim().toLowerCase(Locale.ROOT)));
                    }
                }
                case "--iterations" -> iterations = Integer.parseInt(args[++i]);
                case "--warmup" -> warmup = Integer.parseInt(args[++i]);
                case "--port" -> port = args[++i];
                case "--baud" -> baud = Integer.parseInt(args[++i]);
                case "--out" -> outDir = Path.of(args[++i]);
                case "--message" -> message = args[++i];
                case "--pads" -> pads = Integer.parseInt(args[++i]);
                case "--yes-destructive" -> destructiveOk = true;
                case "--reset-cmd" -> resetCmd = args[++i];
                case "--timeout-sec" -> timeoutSec = Integer.parseInt(args[++i]);
                case "--sae-ca-p12" -> saeCaP12 = Path.of(args[++i]);
                default -> throw new IllegalArgumentException("Unknown option " + args[i] + " (see --help)");
            }
        }
        if (iterations < 1 || warmup < 0 || pads < 1) {
            throw new IllegalArgumentException("iterations >= 1, warmup >= 0, pads >= 1");
        }
        if (!destructiveOk && (benches.contains(Bench.padwrite) || benches.contains(Bench.initlab))) {
            System.err.println("padwrite/initlab are destructive; skipping them (add --yes-destructive to run).");
            benches.remove(Bench.padwrite);
            benches.remove(Bench.initlab);
        }
        if (benches.isEmpty()) {
            System.err.println("Nothing to run.");
            return;
        }

        SeBench bench = new SeBench(message, pads, port, baud, resetCmd, saeCaP12);
        bench.timeoutSec = timeoutSec;
        List<Result> results = new ArrayList<>();
        try {
            for (Bench b : benches) {
                bench.closeLink(); // fresh CDC session per benchmark
                results.add(bench.run(b, iterations, warmup));
            }
        } finally {
            bench.closeLink();
        }
        Path csv = writeCsv(outDir, results);
        System.out.println();
        System.out.printf(Locale.ROOT, "%-10s %4s %10s %10s %10s %10s %10s%n",
                "benchmark", "n", "min ms", "max ms", "mean ms", "median ms", "stddev ms");
        for (Result r : results) {
            r.printSummary();
        }
        System.out.println("CSV: " + csv.toAbsolutePath());
    }

    // ------------------------------------------------------------------ setup

    private final String message;
    private final int pads;
    private SSLContext ownerCtx;
    private SSLContext saeCtx;
    private final SecureRandom random = new SecureRandom();

    private final String port;
    private final int baud;
    private final String resetCmd;
    private final Path saeCaP12;
    private SeUsbLink link;
    private int timeoutSec = 120;

    private SeBench(String message, int pads, String port, int baud, String resetCmd, Path saeCaP12) {
        this.message = message;
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

    private Result run(Bench b, int iterations, int warmup) throws Exception {
        Op op = switch (b) {
            case handshake -> handshakeOp();
            case encrypt -> encryptOp();
            case padwrite -> padWriteOp();
            case initlab -> initLabOp();
        };
        Result result = new Result(b.name());
        System.out.println("== " + b + " (warm-up " + warmup + ", iterations " + iterations + ")");
        for (int i = -warmup; i < iterations; i++) {
            if (b == Bench.initlab && resetCmd != null) {
                reset();
            }
            long t0 = System.nanoTime();
            long inner;
            java.util.concurrent.ExecutorService ex = java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "se-bench-op");
                t.setDaemon(true);
                return t;
            });
            try {
                inner = ex.submit(op::run).get(timeoutSec, java.util.concurrent.TimeUnit.SECONDS);
            } catch (Exception e) {
                Throwable cause = e instanceof java.util.concurrent.ExecutionException && e.getCause() != null
                        ? e.getCause() : e;
                String why = e instanceof java.util.concurrent.TimeoutException
                        ? "timed out after " + timeoutSec + " s" : cause.getMessage();
                System.out.println("   " + b + " iteration " + (i + 1) + " failed: " + why);
                closeLink(); // unblocks a hung read; next iteration reopens
                ex.shutdownNow();
                result.failed++;
                if (b == Bench.initlab && resetCmd == null) {
                    break; // without a reset the next INIT LAB would be refused anyway
                }
                continue;
            }
            ex.shutdown();
            double ms = (inner >= 0 ? inner : System.nanoTime() - t0) / 1e6;
            if (i >= 0) {
                result.samples.add(ms);
                System.out.printf(Locale.ROOT, "   #%d %.2f ms%n", i + 1, ms);
            } else {
                System.out.printf(Locale.ROOT, "   warm-up %.2f ms%n", ms);
            }
        }
        return result;
    }

    private SSLContext ownerCtx() throws Exception {
        if (ownerCtx == null) {
            Path certs = SoftwareTls.certsDir();
            Path p12 = certPath(certs, "USERAPP_OWNER_P12", "user/user.p12");
            if (Files.isRegularFile(p12)) {
                char[] pw = EnvSecrets.envOrScan("USERAPP_OWNER_P12_PASSWORD").toCharArray();
                ownerCtx = SoftwareTls.createContextFromPkcs12(p12, pw, SoftwareTls.clientCaPem());
                Arrays.fill(pw, '\0');
            } else {
                ownerCtx = SoftwareTls.createContextFromPem(
                        certPath(certs, "USERAPP_OWNER_CERT", "user/user-cert.pem"),
                        certPath(certs, "USERAPP_OWNER_KEY", "user/user-key.pem"),
                        SoftwareTls.clientCaPem());
            }
        }
        return ownerCtx;
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

    /** Same call as the user-app ENCRYPT command. */
    private Op encryptOp() throws Exception {
        SSLContext ctx = ownerCtx();
        String pin = EnvSecrets.envOrScan("SEBENCH_PIN");
        return () -> {
            byte[] reply = new ChipService(usb(), ctx).encrypt(pin, message);
            if (reply == null || reply.length == 0) {
                throw new IOException("empty encrypt reply");
            }
            return -1;
        };
    }

    /** SAE side of PROVISION, as in Node.oneProvisionSession, with random pad material. */
    private Op padWriteOp() throws Exception {
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

    /** INIT LAB without the console prompts: ChipInit.enroll(..., Profile.LAB). */
    private Op initLabOp() throws Exception {
        SSLContext ctx = ownerCtx();
        Path certs = SoftwareTls.certsDir();
        Path deviceCert = certPath(certs, "USERAPP_DEVICE_CERT", "client/client-cert.pem");
        Path saeCa = certPath(certs, "USERAPP_SAE_CA", "ca/root-ca.pem");
        Path clientCaP12 = certPath(certs, "USERAPP_CLIENT_CA_P12", "ca/client_ca.p12");
        String clientCaPw = EnvSecrets.envOrScan("USERAPP_CLIENT_CA_P12_PASSWORD");
        String ownerPw = EnvSecrets.envOrScan("SEBENCH_OWNER_PASSWORD");
        String pin = EnvSecrets.envOrScan("SEBENCH_PIN");
        byte[] ownerSpki = PeerCertHash.rawSpkiBits(ownerCert());
        byte[] saeCaDer = TlsStores.readPemCerts(saeCa).get(0).getEncoded();
        Path parent = deviceCert.getParent();
        String deviceCn = parent != null && "client2".equals(parent.getFileName().toString())
                ? SoftwareLeaf.DEVICE_CLIENT_CN_2 : SoftwareLeaf.DEVICE_CLIENT_CN;
        return () -> {
            ChipInit.EnrollResult r = ChipInit.enroll(new OwnerAuth(usb(), ctx), ChipInit.FILE_CERTS,
                    ChipInit.Profile.LAB, new ChipInit.EnrollRequest(
                            ownerPw.getBytes(StandardCharsets.US_ASCII), pin, Optional.empty(),
                            deviceCert, clientCaP12, clientCaPw, deviceCn, ownerSpki, saeCaDer));
            if (!r.ok()) {
                throw new IOException("INIT LAB stopped at " + r.stoppedAt() + ": " + r.message());
            }
            return -1;
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
            System.out.printf(Locale.ROOT, "%-10s %4d %10.2f %10.2f %10.2f %10.2f %10.2f%s%n",
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