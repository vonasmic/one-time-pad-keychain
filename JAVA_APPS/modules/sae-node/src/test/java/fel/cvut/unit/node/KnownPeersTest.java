package fel.cvut.unit.node;

import fel.cvut.node.Address;
import fel.cvut.node.interNodeCommunication.KnownPeers;
import fel.cvut.node.interNodeCommunication.SaeNodes;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** F-02: pinned RMI peer list (SAE ID to leaf SPKI SHA-384). */
@Tag("unit")
class KnownPeersTest {

    @Test
    void fingerprintIsSha384OfSubjectPublicKeyInfo() throws Exception {
        X509Certificate cert = cert("CN=sae-2");
        String expected = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-384").digest(cert.getPublicKey().getEncoded()));
        assertEquals(96, expected.length());
        assertEquals(expected, KnownPeers.spkiSha384(cert));
    }

    @Test
    void mapsPinnedLeafToSaeIdAndIgnoresOthers() throws Exception {
        X509Certificate pinned = cert("CN=sae-2");
        X509Certificate other = cert("CN=sae-2");
        String fp = KnownPeers.spkiSha384(pinned).toUpperCase(Locale.ROOT);
        String colons = fp.replaceAll("(..)(?!$)", "$1:");
        KnownPeers peers = KnownPeers.of("sae-1", Map.of("sae-2", colons));
        assertEquals("sae-1", peers.selfSaeId());
        assertEquals(Optional.of("sae-2"), peers.saeIdFor(pinned));
        assertEquals(Optional.empty(), peers.saeIdFor(other), "same subject, different key: not pinned");
        assertEquals(Optional.empty(), peers.saeIdFor(null));
    }

    @Test
    void rejectsMalformedEntries() throws Exception {
        String fp = KnownPeers.spkiSha384(cert("CN=x"));
        assertThrows(IllegalArgumentException.class, () -> KnownPeers.of("sae-1", Map.of("sae-2", "abcd")));
        assertThrows(IllegalArgumentException.class,
                () -> KnownPeers.of("sae-1", Map.of("sae-2", "zz" + fp.substring(2))));
        assertThrows(IllegalArgumentException.class, () -> KnownPeers.of("sae-1", Map.of(" ", fp)));
        assertThrows(IllegalArgumentException.class, () -> KnownPeers.of(" ", Map.of("sae-2", fp)));
        assertThrows(IllegalArgumentException.class,
                () -> KnownPeers.of("sae-1", Map.of("sae-2", fp, "sae-3", fp)), "one key, two SAE IDs");
    }

    @Test
    void pinsComeFromTheSaeDirectory() throws Exception {
        X509Certificate sae2 = cert("CN=sae-2");
        X509Certificate sae3 = cert("CN=sae-3");
        SaeNodes nodes = SaeNodes.of(List.of(
                new SaeNodes.Entry("sae-2", "Bob", "Berlin", new Address("127.0.0.1", 2020), KnownPeers.spkiSha384(sae2)),
                new SaeNodes.Entry("sae-3", "Carol", "Paris", new Address("127.0.0.1", 2030), KnownPeers.spkiSha384(sae3))));
        KnownPeers peers = KnownPeers.from("sae-1", nodes);
        assertEquals("sae-1", peers.selfSaeId());
        assertEquals(Optional.of("sae-2"), peers.saeIdFor(sae2));
        assertEquals(Optional.of("sae-3"), peers.saeIdFor(sae3));
        assertEquals(Optional.empty(), peers.saeIdFor(cert("CN=sae-3")));
    }

    private static X509Certificate cert(String dn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair keys = kpg.generateKeyPair();
        Date now = new Date();
        X500Name name = new X500Name(dn);
        var builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, now, new Date(now.getTime() + 86_400_000L), name, keys.getPublic());
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
    }
}
